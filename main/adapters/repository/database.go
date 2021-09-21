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
	PostgreSql string = "postgres"
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
func NewSqlDatabaseInfo(dataSourceName, tableName string) (*DatabaseManager, error) {
	pg, err := sql.Open(PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}
	pg.SetMaxOpenConns(100)
	pg.SetMaxIdleConns(70)
	pg.SetConnMaxLifetime(10 * time.Minute)
	if err = pg.Ping(); err != nil {
		return nil, err
	}

	log.Print("preparing postgres usage")

	dbManager := &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db:        pg,
		tableName: tableName,
	}

	if _, err = dbManager.db.Exec(CreateTable(PostgresIdentity, tableName)); err != nil {
		return nil, err
	}

	return dbManager, nil
}

func (dm *DatabaseManager) Exists(uid uuid.UUID, retries int) (bool, error) {
	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&id)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.Exists(uid, increasedRetries)
		}
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	} else {
		return true, nil
	}
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID, retries int) ([]byte, error) {
	var privateKey []byte

	query := fmt.Sprintf("SELECT private_key FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&privateKey)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.GetPrivateKey(uid, increasedRetries)
		}
		return nil, err
	}
	return privateKey, nil
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID, retries int) ([]byte, error) {
	var publicKey []byte

	query := fmt.Sprintf("SELECT public_key FROM %s WHERE uid = $1", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&publicKey)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.GetPublicKey(uid, increasedRetries)
		}
		return nil, err
	}

	return publicKey, nil
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID, retries int) (string, error) {
	var authToken string

	query := fmt.Sprintf("SELECT auth_token FROM %s WHERE uid = $1;", dm.tableName)

	err := dm.db.QueryRow(query, uid.String()).Scan(&authToken)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.GetAuthToken(uid, increasedRetries)
		}
		return "", err
	}

	return authToken, nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return dm.db.BeginTx(ctx, dm.options)
}

var ds = 0
var is = 0

// StartTransactionWithLock starts a transaction and acquires a lock on the row with the specified uuid as key.
// Returns error if row does not exist.
func (dm *DatabaseManager) StartTransactionWithLock(ctx context.Context, uid uuid.UUID, retries int) (transactionCtx interface{}, err error) {
	is++
	fmt.Printf("is:%d\n", is)
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	ds++
	fmt.Println(ds)
	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1 FOR UPDATE NOWAIT;", dm.tableName)

	// lock row FOR UPDATE
	err = tx.QueryRow(query, uid).Scan(&id)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.StartTransactionWithLock(ctx, uid, increasedRetries)
		}
		txErr := tx.Rollback()
		if txErr != nil {
			return nil, fmt.Errorf("%v and %v", err, txErr)
		}
		return nil, err
	}

	return tx, nil
}

func (dm *DatabaseManager) CloseTransaction(transactionCtx interface{}, commit bool) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	if commit {
		return tx.Commit()
	} else {
		return tx.Rollback()
	}
}

func (dm *DatabaseManager) FetchIdentity(transactionCtx interface{}, uid uuid.UUID, retries int) (*ent.Identity, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	var id ent.Identity

	query := fmt.Sprintf("SELECT * FROM %s WHERE uid = $1", dm.tableName)

	err := tx.QueryRow(query, uid.String()).Scan(&id.Uid, &id.PrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.FetchIdentity(tx, uid, increasedRetries)
		}
		return nil, err
	}

	return &id, nil
}

func (dm *DatabaseManager) SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte, retries int) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	query := fmt.Sprintf("UPDATE %s SET signature = $1 WHERE uid = $2;", dm.tableName)

	_, err := tx.Exec(query, &signature, uid.String())
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.SetSignature(tx, uid, signature, increasedRetries)
		}
		return err
	}

	return nil
}

func (dm *DatabaseManager) StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity, retries int) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	// make sure identity does not exist yet
	var id string

	query := fmt.Sprintf("SELECT uid FROM %s WHERE uid = $1 FOR UPDATE NOWAIT;", dm.tableName)

	err := tx.QueryRow(query, identity.Uid).Scan(&id)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.StoreNewIdentity(tx, identity, increasedRetries)
		}
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
			return dm.storeIdentity(tx, identity, retries)
		} else {
			return err
		}
	} else {
		return ErrExists
	}
}

func (dm *DatabaseManager) storeIdentity(tx *sql.Tx, identity *ent.Identity, retries int) error {
	query := fmt.Sprintf(
		"INSERT INTO %s (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		dm.tableName)

	_, err := tx.Exec(query, &identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		increasedRetries, retryReconnect := dm.isConnectionAvailable(retries, err)
		if retryReconnect {
			return dm.storeIdentity(tx, identity, increasedRetries)
		}
		return err
	}

	return nil
}

func (dm *DatabaseManager) isConnectionAvailable(retriesCounter int, err error) (int, bool) {
	if retriesCounter < MaxRetries {
		if err, ok := err.(*pq.Error); ok {
			if err.Code == "55P03" || err.Code == "53400" || err.Code == "53300" {
				time.Sleep(100 * time.Millisecond)
				return retriesCounter + 1, true
			}
		}
	}
	return retriesCounter, false
}
