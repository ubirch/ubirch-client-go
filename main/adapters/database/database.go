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

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"modernc.org/sqlite"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSQL = "postgres"
	SQLite     = "sqlite"

	sqliteConfig = "?_txlock=EXCLUSIVE" + // https://www.sqlite.org/lang_transaction.html
		"&_pragma=journal_mode(WAL)" + // https://www.sqlite.org/wal.html
		"&_pragma=synchronous(FULL)" + // https://www.sqlite.org/pragma.html#pragma_synchronous
		"&_pragma=wal_autocheckpoint(4)" + // checkpoint when WAL reaches x pages https://www.sqlite.org/pragma.html#pragma_wal_autocheckpoint
		"&_pragma=wal_checkpoint(PASSIVE)" + // https://www.sqlite.org/pragma.html#pragma_wal_checkpoint
		"&_pragma=journal_size_limit(32000)" + // max WAL file size in bytes https://www.sqlite.org/pragma.html#pragma_journal_size_limit
		"&_pragma=busy_timeout(100)" // https://www.sqlite.org/pragma.html#pragma_busy_timeout

	maxRetries = 2
)

// DatabaseManager contains the database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options    *sql.TxOptions
	db         *sql.DB
	driverName string
}

// Ensure Database implements the ContextManager interface
var _ repository.ContextManager = (*DatabaseManager)(nil)

// NewDatabaseManager takes a database connection string, returns a new initialized
// SQL database manager.
func NewDatabaseManager(driverName, dataSourceName string, maxConns int, migrate bool) (*DatabaseManager, error) {
	if driverName == "" || dataSourceName == "" {
		return nil, fmt.Errorf("empty database driverName or dataSourceName")
	}

	dm := &DatabaseManager{}

	switch driverName {
	case PostgreSQL:
		dm.driverName = PostgreSQL
		dm.options = &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
		}
	case SQLite:
		dm.driverName = SQLite
		dm.options = &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		}
		if !strings.Contains(dataSourceName, "?") {
			dataSourceName += sqliteConfig
		}
	default:
		return nil, fmt.Errorf("unsupported SQL database driver: %s, supported drivers: %s, %s",
			driverName, PostgreSQL, SQLite)
	}

	log.Infof("initializing %s database connection", driverName)

	var err error

	dm.db, err = sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	dm.db.SetMaxOpenConns(maxConns)
	dm.db.SetMaxIdleConns(maxConns)
	dm.db.SetConnMaxLifetime(10 * time.Minute)
	dm.db.SetConnMaxIdleTime(1 * time.Minute)

	if err = dm.IsReady(); err != nil {
		return nil, err
	}

	// migrate database schema to the latest version
	if migrate {
		err = MigrateUp(dm.db, dm.driverName)
		if err != nil {
			return nil, err
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

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx repository.TransactionCtx, err error) {
	err = dm.retry(func() error {
		transactionCtx, err = dm.db.BeginTx(ctx, dm.options)
		return err
	})
	return transactionCtx, err
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx repository.TransactionCtx, i ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query :=
		"INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);"

	_, err := tx.Exec(query, &i.Uid, &i.PrivateKey, &i.PublicKey, &i.Signature, &i.AuthToken)

	return err
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*ent.Identity, error) {
	i := ent.Identity{Uid: uid}

	query := "SELECT private_key, public_key, signature, auth_token FROM identity WHERE uid = $1;"

	err := dm.retry(func() error {
		err := dm.db.QueryRow(query, uid).Scan(&i.PrivateKey, &i.PublicKey, &i.Signature, &i.AuthToken)
		if err == sql.ErrNoRows {
			return repository.ErrNotExist
		}
		return err
	})

	return &i, err
}

func (dm *DatabaseManager) StoreActiveFlag(transactionCtx repository.TransactionCtx, uid uuid.UUID, active bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "UPDATE identity SET active = $1 WHERE uid = $2;"

	_, err := tx.Exec(query, &active, uid)

	return err
}

func (dm *DatabaseManager) LoadActiveFlagForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (active bool, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "SELECT active FROM identity WHERE uid = $1"

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&active)
	if err == sql.ErrNoRows {
		return false, repository.ErrNotExist
	}

	return active, err
}

func (dm *DatabaseManager) LoadActiveFlag(uid uuid.UUID) (active bool, err error) {
	query := "SELECT active FROM identity WHERE uid = $1;"

	err = dm.retry(func() error {
		err := dm.db.QueryRow(query, uid).Scan(&active)
		if err == sql.ErrNoRows {
			return repository.ErrNotExist
		}
		return err
	})

	return active, err
}

func (dm *DatabaseManager) StoreSignature(transactionCtx repository.TransactionCtx, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "UPDATE identity SET signature = $1 WHERE uid = $2;"

	_, err := tx.Exec(query, &signature, uid)

	return err
}

func (dm *DatabaseManager) LoadSignatureForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (signature []byte, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "SELECT signature FROM identity WHERE uid = $1"

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&signature)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotExist
	}

	return signature, err
}

func (dm *DatabaseManager) StoreAuth(transactionCtx repository.TransactionCtx, uid uuid.UUID, auth string) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "UPDATE identity SET auth_token = $1 WHERE uid = $2;"

	_, err := tx.Exec(query, &auth, uid)

	return err
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := "SELECT auth_token FROM identity WHERE uid = $1"

	if dm.driverName == PostgreSQL {
		query += " FOR UPDATE"
	}
	query += ";"

	err = tx.QueryRow(query, uid).Scan(&auth)
	if err == sql.ErrNoRows {
		return "", repository.ErrNotExist
	}

	return auth, err
}

func (dm *DatabaseManager) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) error {
	query := "INSERT INTO external_identity (uid, public_key) VALUES ($1, $2);"

	err := dm.retry(func() error {
		_, err := dm.db.ExecContext(ctx, query, &extId.Uid, &extId.PublicKey)
		return err
	})

	return err
}

func (dm *DatabaseManager) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (*ent.ExternalIdentity, error) {
	extId := ent.ExternalIdentity{Uid: uid}

	query := "SELECT public_key FROM external_identity WHERE uid = $1;"

	err := dm.retry(func() error {
		err := dm.db.QueryRowContext(ctx, query, uid).Scan(&extId.PublicKey)
		if err == sql.ErrNoRows {
			return repository.ErrNotExist
		}
		return err
	})

	return &extId, err
}

func (dm *DatabaseManager) GetIdentityUUIDs() ([]uuid.UUID, error) {
	return dm.getUUIDs("SELECT uid FROM identity")
}

func (dm *DatabaseManager) GetExternalIdentityUUIDs() ([]uuid.UUID, error) {
	return dm.getUUIDs("SELECT uid FROM external_identity")
}

func (dm *DatabaseManager) getUUIDs(query string) ([]uuid.UUID, error) {
	rows, err := dm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = rows.Close(); err != nil {
			log.Error(err)
		}
	}()

	var (
		id  uuid.UUID
		ids []uuid.UUID
	)

	for rows.Next() {
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, rows.Err()
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
			}
			log.Errorf("unexpected postgres database error: %s", pqErr)
		}
	case SQLite:
		if liteErr, ok := err.(*sqlite.Error); ok {
			if liteErr.Code() == 5 || // SQLITE_BUSY
				liteErr.Code() == 6 || // SQLITE_LOCKED
				liteErr.Code() == 261 { // SQLITE_BUSY_RECOVERY
				time.Sleep(10 * time.Millisecond)
				return true
			}
			log.Errorf("unexpected sqlite database error: %s", liteErr)
		}
	}
	return false
}
