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

	defaultDbMaxOpenConns       = 0 // unlimited
	defaultDbMaxIdleConns       = 10
	defaultDbConnMaxLifetimeSec = 10 * 60
	defaultDbConnMaxIdleTimeSec = 1 * 60
)

// DatabaseManager contains the database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options    *sql.TxOptions
	dbConn     *sql.DB
	driverName string

	db Querier
}

// Ensure Database implements the ContextManager interface
var _ repository.ContextManager = (*DatabaseManager)(nil)

type ConnectionParams struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// NewDatabaseManager takes a database connection string, returns a new initialized
// SQL database manager.
func NewDatabaseManager(driverName, dataSourceName string, params *ConnectionParams) (*DatabaseManager, error) {
	if driverName == "" || dataSourceName == "" {
		return nil, fmt.Errorf("empty database driverName or dataSourceName")
	}

	// migrate database schema to the latest version
	err := migrateUp(driverName, dataSourceName)
	if err != nil {
		return nil, err
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

	dm.dbConn, err = sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	dm.SetConnectionParams(params)

	dm.db = NewQuerier(dm.dbConn, driverName)

	if err = dm.IsReady(); err != nil {
		return nil, err
	}

	return dm, nil
}

func (dm *DatabaseManager) SetConnectionParams(params *ConnectionParams) {
	if params.MaxOpenConns == 0 {
		params.MaxOpenConns = defaultDbMaxOpenConns
	}
	dm.dbConn.SetMaxOpenConns(params.MaxOpenConns)

	if params.MaxIdleConns == 0 {
		params.MaxIdleConns = defaultDbMaxIdleConns
	}
	dm.dbConn.SetMaxIdleConns(params.MaxIdleConns)

	if params.ConnMaxLifetime == 0 {
		params.ConnMaxLifetime = defaultDbConnMaxLifetimeSec * time.Second
	}
	dm.dbConn.SetConnMaxLifetime(params.ConnMaxLifetime)

	if params.ConnMaxIdleTime == 0 {
		params.ConnMaxIdleTime = defaultDbConnMaxIdleTimeSec * time.Second
	}
	dm.dbConn.SetConnMaxIdleTime(params.ConnMaxIdleTime)
}

func (dm *DatabaseManager) Close() error {
	err := dm.dbConn.Close()
	if err != nil {
		return fmt.Errorf("failed to close database: %v", err)
	}
	return nil
}

func (dm *DatabaseManager) IsReady() error {
	return dm.dbConn.Ping()
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx repository.TransactionCtx, err error) {
	err = dm.retry(func() error {
		transactionCtx, err = dm.dbConn.BeginTx(ctx, dm.options)
		return err
	})
	return transactionCtx, err
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx repository.TransactionCtx, i ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	return dm.db.StoreIdentity(tx, StoreIdentityParams(i))
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*ent.Identity, error) {
	var (
		identity ent.Identity
		err      error
	)

	err = dm.retry(func() error {
		identity, err = dm.db.LoadIdentity(context.Background(), uid)
		if err == sql.ErrNoRows {
			return repository.ErrNotExist
		}
		return err
	})
	return &identity, err
}

func (dm *DatabaseManager) StoreActiveFlag(transactionCtx repository.TransactionCtx, uid uuid.UUID, active bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	return dm.db.StoreActiveFlag(tx, StoreActiveFlagParams{
		Uid:    uid,
		Active: active,
	})
}

func (dm *DatabaseManager) LoadActiveFlagForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (bool, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	active, err := dm.db.LoadActiveFlagForUpdate(tx, uid)
	if err == sql.ErrNoRows {
		return false, repository.ErrNotExist
	}
	return active, err
}

func (dm *DatabaseManager) LoadActiveFlag(uid uuid.UUID) (active bool, err error) {
	err = dm.retry(func() error {
		active, err = dm.db.LoadActiveFlag(context.Background(), uid)
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

	return dm.db.StoreSignature(tx, StoreSignatureParams{
		Uid:       uid,
		Signature: signature,
	})
}

func (dm *DatabaseManager) LoadSignatureForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) ([]byte, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	signature, err := dm.db.LoadSignatureForUpdate(tx, uid)
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

	return dm.db.StoreAuth(tx, StoreAuthParams{
		Uid:       uid,
		AuthToken: auth,
	})
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (string, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	auth, err := dm.db.LoadAuthForUpdate(tx, uid)
	if err == sql.ErrNoRows {
		return "", repository.ErrNotExist
	}
	return auth, err
}

func (dm *DatabaseManager) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) error {
	err := dm.retry(func() error {
		return dm.db.StoreExternalIdentity(ctx, StoreExternalIdentityParams(extId))
	})

	return err
}

func (dm *DatabaseManager) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (*ent.ExternalIdentity, error) {
	var (
		extIdentity ent.ExternalIdentity
		err         error
	)

	err = dm.retry(func() error {
		extIdentity, err = dm.db.LoadExternalIdentity(ctx, uid)
		if err == sql.ErrNoRows {
			return repository.ErrNotExist
		}
		return err
	})

	return &extIdentity, err
}

func (dm *DatabaseManager) GetIdentityUUIDs() ([]uuid.UUID, error) {
	return dm.db.GetIdentityUUIDs(context.Background())
}

func (dm *DatabaseManager) GetExternalIdentityUUIDs() ([]uuid.UUID, error) {
	return dm.db.GetExternalIdentityUUIDs(context.Background())
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
			if pqErr.Code == "55P03" || // lock_not_available
				pqErr.Code == "53300" || // too_many_connections
				pqErr.Code == "53400" { // configuration_limit_exceeded
				time.Sleep(10 * time.Millisecond)
				return true
			}
			log.Errorf("unexpected postgres database error: %v", pqErr)
		}
	case SQLite:
		if liteErr, ok := err.(*sqlite.Error); ok {
			if liteErr.Code() == 5 || // SQLITE_BUSY
				liteErr.Code() == 6 || // SQLITE_LOCKED
				liteErr.Code() == 261 { // SQLITE_BUSY_RECOVERY
				time.Sleep(10 * time.Millisecond)
				return true
			}
			log.Errorf("unexpected sqlite database error: %v", liteErr)
		}
	}
	return false
}
