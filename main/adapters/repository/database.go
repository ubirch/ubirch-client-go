// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"modernc.org/sqlite"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSQL = "postgres"
	SQLite     = "sqlite"

	sqliteConfig = "?_txlock=exclusive" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=busy_timeout(1000)"
	maxRetries = 2
)

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options    *sql.TxOptions
	db         *sql.DB
	driverName string
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewDatabaseManager takes a database connection string, returns a new initialized
// SQL database manager.
func NewDatabaseManager(driverName, dataSourceName string, maxConns int) (*DatabaseManager, error) {
	log.Infof("preparing %s database", driverName)

	var isolationLvl sql.IsolationLevel
	var identityTable int

	switch driverName {
	case PostgreSQL:
		isolationLvl = sql.LevelReadCommitted
		identityTable = PostgresIdentity
	case SQLite:
		isolationLvl = sql.LevelSerializable
		identityTable = SQLiteIdentity
		if !strings.Contains(dataSourceName, "?") {
			dataSourceName += sqliteConfig
		}
	default:
		return nil, fmt.Errorf("unsupported SQL driver: %s", driverName)
	}

	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(10 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	dm := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: isolationLvl,
			ReadOnly:  false,
		},
		db:         db,
		driverName: driverName,
	}

	if err = dm.IsReady(); err != nil {
		// if there is no connection to the database yet, continue anyway.
		log.Warn(err)
	} else {
		err = dm.CreateTable(identityTable)
		if err != nil {
			return nil, fmt.Errorf("creating DB table failed: %v", err)
		}
	}

	return dm, nil
}

func (dm *DatabaseManager) Close() error {
	err := dm.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close database: %v", err)
	}
	return nil
}

func (dm *DatabaseManager) IsReady() error {
	if err := dm.db.Ping(); err != nil {
		return fmt.Errorf("database not ready: %v", err)
	}
	return nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx TransactionCtx, err error) {
	err = dm.retry(func() error {
		transactionCtx, err = dm.db.BeginTx(ctx, dm.options)
		return err
	})
	return transactionCtx, err
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx TransactionCtx, i ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		IdentityTableName)

	_, err := tx.Exec(query, &i.Uid, &i.PrivateKey, &i.PublicKey, &i.Signature, &i.AuthToken)

	return err
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*ent.Identity, error) {
	i := ent.Identity{Uid: uid}

	query := fmt.Sprintf(
		"SELECT private_key, public_key, signature, auth_token FROM %s WHERE uid = $1;",
		IdentityTableName)

	err := dm.retry(func() error {
		err := dm.db.QueryRow(query, uid).Scan(&i.PrivateKey, &i.PublicKey, &i.Signature, &i.AuthToken)
		if err == sql.ErrNoRows {
			return ErrNotExist
		}
		return err
	})

	return &i, err
}

func (dm *DatabaseManager) StoreActiveFlag(transactionCtx TransactionCtx, uid uuid.UUID, active bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET active = $1 WHERE uid = $2;", IdentityTableName)

	_, err := tx.Exec(query, &active, uid)

	return err
}

func (dm *DatabaseManager) LoadActiveFlagForUpdate(transactionCtx TransactionCtx, uid uuid.UUID) (active bool, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT active FROM %s WHERE uid = $1", IdentityTableName)

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&active)
	if err == sql.ErrNoRows {
		return false, ErrNotExist
	}

	return active, err
}

func (dm *DatabaseManager) LoadActiveFlag(uid uuid.UUID) (active bool, err error) {
	query := fmt.Sprintf("SELECT active FROM %s WHERE uid = $1;", IdentityTableName)

	err = dm.db.QueryRow(query, uid).Scan(&active)
	if err == sql.ErrNoRows {
		return false, ErrNotExist
	}

	return active, err
}

func (dm *DatabaseManager) StoreSignature(transactionCtx TransactionCtx, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET signature = $1 WHERE uid = $2;", IdentityTableName)

	_, err := tx.Exec(query, &signature, uid)

	return err
}

func (dm *DatabaseManager) LoadSignatureForUpdate(transactionCtx TransactionCtx, uid uuid.UUID) (signature []byte, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT signature FROM %s WHERE uid = $1", IdentityTableName)

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&signature)
	if err == sql.ErrNoRows {
		return nil, ErrNotExist
	}

	return signature, err
}

func (dm *DatabaseManager) StoreAuth(transactionCtx TransactionCtx, uid uuid.UUID, auth string) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET auth_token = $1 WHERE uid = $2;", IdentityTableName)

	_, err := tx.Exec(query, &auth, uid)

	return err
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT auth_token FROM %s WHERE uid = $1", IdentityTableName)

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&auth)
	if err == sql.ErrNoRows {
		return "", ErrNotExist
	}

	return auth, err
}

func (dm *DatabaseManager) retry(f func() error) (err error) {
	for retries := 0; retries <= maxRetries; retries++ {
		err = f()
		if err == nil || !dm.isRecoverable(err) {
			break
		}
		log.Warnf("database recoverable error: %v (%d / %d)", err, retries+1, maxRetries+1)
	}

	return err
}

func (dm *DatabaseManager) isRecoverable(err error) bool {
	switch dm.driverName {
	case PostgreSQL:
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "55P03", "53300", "53400": // lock_not_available, too_many_connections, configuration_limit_exceeded
				time.Sleep(10 * time.Millisecond)
				return true
			case "42P01": // undefined_table
				err = dm.CreateTable(PostgresIdentity)
				if err != nil {
					log.Errorf("creating DB table failed: %v", err)
				}
				return true
			}
			log.Errorf("unexpected postgres database error: %s", pqErr)
		}
	case SQLite:
		if liteErr, ok := err.(*sqlite.Error); ok {
			if liteErr.Code() == 5 || // SQLITE_BUSY
				liteErr.Code() == 6 || // SQLITE_LOCKED
				liteErr.Code() == 261 { // SQLITE_BUSY_RECOVERY
				time.Sleep(100 * time.Millisecond)
				return true
			}
			if liteErr.Code() == 1 { // SQLITE_ERROR
				err = dm.CreateTable(SQLiteIdentity)
				if err != nil {
					log.Errorf("creating DB table failed: %v", err)
				}
				return true
			}
			log.Errorf("unexpected sqlite database error: %s", liteErr)
		}
	}
	return false
}
