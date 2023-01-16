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
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/postgres"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/sqlite"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"

	postgresLib "github.com/lib/pq"
	sqliteLib "modernc.org/sqlite"

	log "github.com/sirupsen/logrus"
)

type driverName string

const (
	postgresDriver driverName = "postgres"
	sqliteDriver   driverName = "sqlite"

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
	driver  driverName
	db      *sql.DB
	options *sql.TxOptions

	postgres *postgres.Queries
	sqlite   *sqlite.Queries
}

// Ensure Database implements the ContextManager interface
var _ repository.ContextManager = (*DatabaseManager)(nil)

// NewDatabaseManager takes a database connection string, returns a new initialized
// SQL database manager.
func NewDatabaseManager(driverName, dataSourceName string, maxConns int, establishConnTimeoutSec uint, migrate bool) (*DatabaseManager, error) {
	if driverName == "" || dataSourceName == "" {
		return nil, fmt.Errorf("empty database driverName or dataSourceName")
	}
	if establishConnTimeoutSec == 0 {
		establishConnTimeoutSec = 1
	}

	dm := &DatabaseManager{}

	switch driverName {
	case "postgres":
		dm.driver = postgresDriver
	case "sqlite":
		dm.driver = sqliteDriver
		if !strings.Contains(dataSourceName, "?") {
			dataSourceName += sqliteConfig
		}
	default:
		return nil, fmt.Errorf("unsupported SQL database driver: %s, supported drivers: {postgres | sqlite}",
			driverName)
	}

	log.Infof("initializing %s database connection", driverName)

	var err error

	dm.db, err = sql.Open(string(dm.driver), dataSourceName)
	if err != nil {
		return nil, err
	}

	dm.db.SetMaxOpenConns(maxConns)
	dm.db.SetMaxIdleConns(maxConns)
	dm.db.SetConnMaxLifetime(10 * time.Minute)
	dm.db.SetConnMaxIdleTime(1 * time.Minute)

	switch dm.driver {
	case postgresDriver:
		dm.options = &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
		}

		dm.postgres = postgres.New(dm.db)
	case sqliteDriver:
		dm.options = &sql.TxOptions{
			Isolation: sql.LevelLinearizable,
		}

		dm.sqlite = sqlite.New(dm.db)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(establishConnTimeoutSec)*time.Second)
	defer cancel()

	if err = dm.IsReady(ctx); err != nil {
		if dm.driver == postgresDriver && os.IsTimeout(err) {
			// if there is no connection to the database yet, continue anyway.
			log.Warnf("connection to the database could not yet be established: %v", err)
		} else {
			return nil, err
		}
	}

	// migrate database schema to the latest version
	if migrate {
		err = dm.db.Ping()
		if err != nil {
			return nil, err
		}

		err = MigrateUp(dm.db, dm.driver)
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

func (dm *DatabaseManager) IsReady(ctx context.Context) error {
	return dm.db.PingContext(ctx)
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

	switch dm.driver {
	case postgresDriver:
		return dm.postgres.WithTx(tx).StoreIdentity(context.Background(), postgres.StoreIdentityParams(i))
	case sqliteDriver:
		return dm.sqlite.WithTx(tx).StoreIdentity(context.Background(), sqlite.StoreIdentityParams{
			Uid:        i.Uid.String(),
			PrivateKey: i.PrivateKey,
			PublicKey:  i.PublicKey,
			Signature:  i.Signature,
			AuthToken:  i.AuthToken,
			Active:     sqliteBoolToInt64(i.Active),
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (identity ent.Identity, err error) {
	err = dm.retry(func() error {
		identity, err = dm.loadIdentity(uid)
		return err
	})
	return identity, err
}

func (dm *DatabaseManager) loadIdentity(uid uuid.UUID) (ent.Identity, error) {
	switch dm.driver {
	case postgresDriver:
		i, err := dm.postgres.LoadIdentity(context.Background(), uid)
		if err == sql.ErrNoRows {
			return ent.Identity{}, repository.ErrNotExist
		}
		return ent.Identity(i), err
	case sqliteDriver:
		i, err := dm.sqlite.LoadIdentity(context.Background(), uid.String())
		if err == sql.ErrNoRows {
			return ent.Identity{}, repository.ErrNotExist
		}
		if err != nil {
			return ent.Identity{}, err
		}
		return ent.Identity{
			Uid:        uuid.MustParse(i.Uid), // todo use Parse and handle error
			PrivateKey: i.PrivateKey,
			PublicKey:  i.PublicKey,
			Signature:  i.Signature,
			AuthToken:  i.AuthToken,
			Active:     sqliteInt64ToBool(i.Active),
		}, err
	default:
		return ent.Identity{}, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) StoreActiveFlag(transactionCtx repository.TransactionCtx, uid uuid.UUID, active bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	switch dm.driver {
	case postgresDriver:
		return dm.postgres.WithTx(tx).StoreActiveFlag(context.Background(), postgres.StoreActiveFlagParams{
			Uid:    uid,
			Active: active,
		})
	case sqliteDriver:
		return dm.sqlite.WithTx(tx).StoreActiveFlag(context.Background(), sqlite.StoreActiveFlagParams{
			Uid:    uid.String(),
			Active: sqliteBoolToInt64(active),
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) LoadActiveFlagForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (bool, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	switch dm.driver {
	case postgresDriver:
		active, err := dm.postgres.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid)
		if err == sql.ErrNoRows {
			return false, repository.ErrNotExist
		}
		return active, err
	case sqliteDriver:
		active, err := dm.sqlite.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid.String())
		if err == sql.ErrNoRows {
			return false, repository.ErrNotExist
		}
		return sqliteInt64ToBool(active), err
	default:
		return false, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) LoadActiveFlag(uid uuid.UUID) (active bool, err error) {
	err = dm.retry(func() error {
		active, err = dm.loadActiveFlag(uid)
		return err
	})
	return active, err
}

func (dm *DatabaseManager) loadActiveFlag(uid uuid.UUID) (bool, error) {
	switch dm.driver {
	case postgresDriver:
		active, err := dm.postgres.LoadActiveFlag(context.Background(), uid)
		if err == sql.ErrNoRows {
			return false, repository.ErrNotExist
		}
		return active, err
	case sqliteDriver:
		active, err := dm.sqlite.LoadActiveFlag(context.Background(), uid.String())
		if err == sql.ErrNoRows {
			return false, repository.ErrNotExist
		}
		return sqliteInt64ToBool(active), err
	default:
		return false, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) StoreSignature(transactionCtx repository.TransactionCtx, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	switch dm.driver {
	case postgresDriver:
		return dm.postgres.WithTx(tx).StoreSignature(context.Background(), postgres.StoreSignatureParams{
			Uid:       uid,
			Signature: signature,
		})
	case sqliteDriver:
		return dm.sqlite.WithTx(tx).StoreSignature(context.Background(), sqlite.StoreSignatureParams{
			Uid:       uid.String(),
			Signature: signature,
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) LoadSignatureForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (signature []byte, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	switch dm.driver {
	case postgresDriver:
		signature, err = dm.postgres.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid)
	case sqliteDriver:
		signature, err = dm.sqlite.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid.String())
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}

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

	switch dm.driver {
	case postgresDriver:
		return dm.postgres.WithTx(tx).StoreAuth(context.Background(), postgres.StoreAuthParams{
			Uid:       uid,
			AuthToken: auth,
		})
	case sqliteDriver:
		return dm.sqlite.WithTx(tx).StoreAuth(context.Background(), sqlite.StoreAuthParams{
			Uid:       uid.String(),
			AuthToken: auth,
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	switch dm.driver {
	case postgresDriver:
		auth, err = dm.postgres.WithTx(tx).LoadAuthForUpdate(context.Background(), uid)
	case sqliteDriver:
		auth, err = dm.sqlite.WithTx(tx).LoadAuthForUpdate(context.Background(), uid.String())
	default:
		return "", fmt.Errorf("unsupported database driver: %s", dm.driver)
	}

	if err == sql.ErrNoRows {
		return "", repository.ErrNotExist
	}
	return auth, err
}

func (dm *DatabaseManager) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) error {
	err := dm.retry(func() error {
		switch dm.driver {
		case postgresDriver:
			return dm.postgres.StoreExternalIdentity(ctx, postgres.StoreExternalIdentityParams(extId))
		case sqliteDriver:
			return dm.sqlite.StoreExternalIdentity(ctx, sqlite.StoreExternalIdentityParams{
				Uid:       extId.Uid.String(),
				PublicKey: extId.PublicKey,
			})
		default:
			return fmt.Errorf("unsupported database driver: %s", dm.driver)
		}
	})

	return err
}

func (dm *DatabaseManager) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (extIdentity ent.ExternalIdentity, err error) {
	err = dm.retry(func() error {
		extIdentity, err = dm.loadExternalIdentity(ctx, uid)
		return err
	})

	return extIdentity, err
}

func (dm *DatabaseManager) loadExternalIdentity(ctx context.Context, uid uuid.UUID) (ent.ExternalIdentity, error) {
	switch dm.driver {
	case postgresDriver:
		i, err := dm.postgres.LoadExternalIdentity(ctx, uid)
		if err == sql.ErrNoRows {
			return ent.ExternalIdentity{}, repository.ErrNotExist
		}
		return ent.ExternalIdentity(i), err
	case sqliteDriver:
		i, err := dm.sqlite.LoadExternalIdentity(ctx, uid.String())
		if err == sql.ErrNoRows {
			return ent.ExternalIdentity{}, repository.ErrNotExist
		}
		if err != nil {
			return ent.ExternalIdentity{}, err
		}
		return ent.ExternalIdentity{
			Uid:       uuid.MustParse(i.Uid), // todo use Parse and handle error
			PublicKey: i.PublicKey,
		}, err
	default:
		return ent.ExternalIdentity{}, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) GetIdentityUUIDs() ([]uuid.UUID, error) {
	switch dm.driver {
	case postgresDriver:
		return dm.postgres.GetIdentityUUIDs(context.Background())

	case sqliteDriver:
		// return db.sqlite.GetIdentityUUIDs(context.Background())

		uuidStrings, err := dm.sqlite.GetIdentityUUIDs(context.Background())
		if err != nil {
			return nil, err
		}

		// convert UUIDs from string representation to uuid.UUID type
		// todo: this is a workaround until kyleconroy/sqlc supports overrides for sqlite
		//  related issue: https://github.com/kyleconroy/sqlc/issues/1985
		//  may be fixed by https://github.com/kyleconroy/sqlc/pull/1986
		var uuids []uuid.UUID
		for _, uidString := range uuidStrings {
			uid, err := uuid.Parse(uidString)
			if err != nil {
				return nil, err
			}
			uuids = append(uuids, uid)
		}
		return uuids, nil

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
}

func (dm *DatabaseManager) GetExternalIdentityUUIDs() ([]uuid.UUID, error) {
	switch dm.driver {
	case postgresDriver:
		return dm.postgres.GetExternalIdentityUUIDs(context.Background())

	case sqliteDriver:
		// return db.sqlite.GetExternalIdentityUUIDs(context.Background())

		uuidStrings, err := dm.sqlite.GetExternalIdentityUUIDs(context.Background())
		if err != nil {
			return nil, err
		}

		// convert UUIDs from string representation to uuid.UUID type
		// todo: this is a workaround until kyleconroy/sqlc supports overrides for sqlite
		//  related issue: https://github.com/kyleconroy/sqlc/issues/1985
		//  may be fixed by https://github.com/kyleconroy/sqlc/pull/1986
		var uuids []uuid.UUID
		for _, uidString := range uuidStrings {
			uid, err := uuid.Parse(uidString)
			if err != nil {
				return nil, err
			}
			uuids = append(uuids, uid)
		}
		return uuids, nil

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", dm.driver)
	}
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
	switch dm.driver {
	case postgresDriver:
		if pgErr, ok := err.(*postgresLib.Error); ok {
			if pgErr.Code == "55P03" || // lock_not_available
				pgErr.Code == "53300" || // too_many_connections
				pgErr.Code == "53400" { // configuration_limit_exceeded
				time.Sleep(10 * time.Millisecond)
				return true
			}
			log.Errorf("unexpected postgres database error: %v", pgErr)
		}
	case sqliteDriver:
		if liteErr, ok := err.(*sqliteLib.Error); ok {
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

// this is a helper function to convert booleans to integers representing booleans in sqlite
func sqliteBoolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// this is a helper function to convert integers representing booleans in sqlite to booleans
func sqliteInt64ToBool(i int64) bool {
	return i != 0
}
