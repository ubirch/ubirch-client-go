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
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

const (
	PostgreSql = "postgres"
	maxRetries = 2
)

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options   *sql.TxOptions
	db        *sql.DB
	tableName string
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dataSourceName, tableName string, maxConns int) (*DatabaseManager, error) {
	log.Infof("preparing postgres usage")

	pg, err := sql.Open(PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}

	pg.SetMaxOpenConns(maxConns)
	pg.SetMaxIdleConns(maxConns)
	pg.SetConnMaxLifetime(10 * time.Minute)
	pg.SetConnMaxIdleTime(1 * time.Minute)

	if err = pg.Ping(); err != nil {
		return nil, err
	}

	dm := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: tableName,
	}

	if _, err = dm.db.Exec(CreateTable(PostgresIdentity, tableName)); err != nil {
		return nil, fmt.Errorf("creating DB table failed: %v", err)
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

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx TransactionCtx, err error) {
	err = retry(func() error {
		transactionCtx, err = dm.db.BeginTx(ctx, dm.options)
		return err
	})
	return transactionCtx, err
}

func (dm *DatabaseManager) StoreNewIdentity(transactionCtx TransactionCtx, identity ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		dm.tableName)

	_, err := tx.Exec(query, &identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) GetSignature(transactionCtx TransactionCtx, uid uuid.UUID) (signature []byte, err error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("SELECT signature FROM %s WHERE uid = $1 FOR UPDATE", dm.tableName)

	err = tx.QueryRow(query, uid).Scan(&signature)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotExist
		}
		return nil, err
	}

	return signature, nil
}

func (dm *DatabaseManager) SetSignature(transactionCtx TransactionCtx, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET signature = $1 WHERE uid = $2;", dm.tableName)

	_, err := tx.Exec(query, &signature, uid)
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) (privateKey []byte, err error) {
	err = retry(func() error {
		query := fmt.Sprintf("SELECT private_key FROM %s WHERE uid = $1", dm.tableName)

		err := dm.db.QueryRow(query, uid).Scan(&privateKey)
		if err != nil {
			if err == sql.ErrNoRows {
				return ErrNotExist
			}
			return err
		}
		return nil
	})

	return privateKey, err
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) (publicKey []byte, err error) {
	err = retry(func() error {
		query := fmt.Sprintf("SELECT public_key FROM %s WHERE uid = $1", dm.tableName)

		err := dm.db.QueryRow(query, uid).Scan(&publicKey)
		if err != nil {
			if err == sql.ErrNoRows {
				return ErrNotExist
			}
			return err
		}
		return nil
	})

	return publicKey, err
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (authToken string, err error) {
	err = retry(func() error {
		query := fmt.Sprintf("SELECT auth_token FROM %s WHERE uid = $1", dm.tableName)

		err := dm.db.QueryRow(query, uid).Scan(&authToken)
		if err != nil {
			if err == sql.ErrNoRows {
				return ErrNotExist
			}
			return err
		}
		return nil
	})

	return authToken, err
}

func retry(f func() error) (err error) {
	for retries := 0; retries <= maxRetries; retries++ {
		err = f()
		if err == nil || !isRecoverable(err) {
			break
		}
		log.Warnf("database recoverable error: %v (%d / %d)", err, retries, maxRetries)
	}

	return err
}

func isRecoverable(err error) bool {
	if err.Error() == pq.ErrorCode("53300").Name() || // "53300": "too_many_connections",
		err.Error() == pq.ErrorCode("53400").Name() { // "53400": "configuration_limit_exceeded",
		time.Sleep(10 * time.Millisecond)
		return true
	}
	return false
}
