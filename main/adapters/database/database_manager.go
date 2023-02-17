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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

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
	db *gorm.DB
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

	log.Infof("initializing %s database connection", driverName)

	var gormDialector gorm.Dialector

	switch driverName {
	case PostgreSQL:
		gormDialector = postgres.Open(dataSourceName)
	case SQLite:
		if !strings.Contains(dataSourceName, "?") {
			dataSourceName += sqliteConfig
		}
		gormDialector = sqlite.Open(dataSourceName)
	default:
		return nil, fmt.Errorf("unsupported SQL database driver: %s, supported drivers: %s, %s",
			driverName, PostgreSQL, SQLite)
	}

	db, err := gorm.Open(gormDialector, &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, err
	}

	dm := &DatabaseManager{
		db: db,
	}

	if err = dm.Setup(); err != nil {
		return nil, err
	}

	if err = dm.SetConnectionParams(params); err != nil {
		return nil, err
	}

	if err = dm.IsReady(); err != nil {
		return nil, err
	}

	return dm, nil
}

func (dm *DatabaseManager) Setup() error {
	err := dm.db.AutoMigrate(&ent.Identity{})
	if err != nil {
		return err
	}

	err = dm.db.AutoMigrate(&ent.ExternalIdentity{})
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) SetConnectionParams(params *ConnectionParams) error {
	db, err := dm.db.DB()
	if err != nil {
		return err
	}

	if params.MaxOpenConns == 0 {
		params.MaxOpenConns = defaultDbMaxOpenConns
	}
	db.SetMaxOpenConns(params.MaxOpenConns)

	if params.MaxIdleConns == 0 {
		params.MaxIdleConns = defaultDbMaxIdleConns
	}
	db.SetMaxIdleConns(params.MaxIdleConns)

	if params.ConnMaxLifetime == 0 {
		params.ConnMaxLifetime = defaultDbConnMaxLifetimeSec * time.Second
	}
	db.SetConnMaxLifetime(params.ConnMaxLifetime)

	if params.ConnMaxIdleTime == 0 {
		params.ConnMaxIdleTime = defaultDbConnMaxIdleTimeSec * time.Second
	}
	db.SetConnMaxIdleTime(params.ConnMaxIdleTime)

	return nil
}

func (dm *DatabaseManager) Close() error {
	db, err := dm.db.DB()
	if err != nil {
		return err
	}

	err = db.Close()
	if err != nil {
		return fmt.Errorf("failed to close database: %v", err)
	}
	return nil
}

func (dm *DatabaseManager) IsReady() error {
	db, err := dm.db.DB()
	if err != nil {
		return err
	}

	return db.Ping()
}

type TX struct {
	db *gorm.DB
}

func (tx *TX) Rollback() error {
	return tx.db.Rollback().Error
}

func (tx *TX) Commit() error {
	return tx.db.Commit().Error
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx repository.TransactionCtx, err error) {
	var tx *gorm.DB
	err = dm.retry(func() error {
		tx = dm.db.WithContext(ctx).Begin()
		return tx.Error
	})

	return &TX{tx}, err
}

func (dm *DatabaseManager) StoreIdentity(transactionCtx repository.TransactionCtx, i ent.Identity) error {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	return tx.db.Create(&i).Error
}

func (dm *DatabaseManager) LoadIdentity(uid uuid.UUID) (*ent.Identity, error) {
	var identity ent.Identity

	err := dm.retry(func() error {
		err := dm.db.Model(&ent.Identity{}).Where("uid = ?", uid).Take(&identity).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return repository.ErrNotExist
		}
		return err
	})
	return &identity, err
}

func (dm *DatabaseManager) StoreActiveFlag(transactionCtx repository.TransactionCtx, uid uuid.UUID, active bool) error {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	return tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Update("active", active).Error
}

func (dm *DatabaseManager) LoadActiveFlagForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (active bool, err error) {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return false, fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	err = tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Select("active").Take(&active).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, repository.ErrNotExist
	}
	return active, err
}

func (dm *DatabaseManager) LoadActiveFlag(uid uuid.UUID) (active bool, err error) {
	err = dm.retry(func() error {
		err := dm.db.Model(&ent.Identity{}).Where("uid = ?", uid).Select("active").Take(&active).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return repository.ErrNotExist
		}
		return err
	})
	return active, err
}

func (dm *DatabaseManager) StoreSignature(transactionCtx repository.TransactionCtx, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	return tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Update("signature", signature).Error
}

func (dm *DatabaseManager) LoadSignatureForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) ([]byte, error) {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	var identity ent.Identity

	err := tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Select("signature").Take(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, repository.ErrNotExist
	}
	return identity.Signature, err
}

func (dm *DatabaseManager) StoreAuth(transactionCtx repository.TransactionCtx, uid uuid.UUID, auth string) error {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	return tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Update("auth_token", auth).Error
}

func (dm *DatabaseManager) LoadAuthForUpdate(transactionCtx repository.TransactionCtx, uid uuid.UUID) (auth string, err error) {
	tx, ok := transactionCtx.(*TX)
	if !ok {
		return "", fmt.Errorf("transactionCtx for database manager is not of expected type *TX")
	}

	err = tx.db.Model(&ent.Identity{}).Where("uid = ?", uid).Select("auth_token").Take(&auth).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", repository.ErrNotExist
	}
	return auth, err
}

func (dm *DatabaseManager) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) error {
	err := dm.retry(func() error {
		return dm.db.WithContext(ctx).Create(&extId).Error
	})

	return err
}

func (dm *DatabaseManager) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (*ent.ExternalIdentity, error) {
	var extIdentity ent.ExternalIdentity

	err := dm.retry(func() error {
		err := dm.db.WithContext(ctx).Model(&ent.ExternalIdentity{}).Where("uid = ?", uid).Take(&extIdentity).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return repository.ErrNotExist
		}
		return err
	})

	return &extIdentity, err
}

func (dm *DatabaseManager) GetIdentityUUIDs() (uids []uuid.UUID, err error) {
	err = dm.db.Model(&ent.Identity{}).Select("uid").Find(&uids).Error
	return uids, err
}

func (dm *DatabaseManager) GetExternalIdentityUUIDs() (uids []uuid.UUID, err error) {
	err = dm.db.Model(&ent.ExternalIdentity{}).Select("uid").Find(&uids).Error
	return uids, err
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
	log.Errorf("%#v", err) // fixme

	time.Sleep(10 * time.Millisecond)
	return true
}
