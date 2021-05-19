package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"time"
)

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

// DatabaseManagerSqlite contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManagerSqlite struct {
	options *sql.TxOptions
	db      *sql.DB
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManagerSqlite)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqliteDatabaseInfo(conf config.Config) (*DatabaseManagerSqlite, error) {
	db, err := sql.Open(vars.Sqlite, "./foo.db")
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(70)
	db.SetConnMaxLifetime(10 * time.Minute)
	if err = db.Ping(); err != nil {
		return nil, err
	}

	log.Print("preparing sqlite usage")

	return &DatabaseManagerSqlite{
		options: &sql.TxOptions{
			Isolation: sql.LevelSerializable,
			ReadOnly:  false,
		},
		db: db,
	}, nil
}

func (dm *DatabaseManagerSqlite) Exists(uid uuid.UUID) (bool, error) {
	var id string

	err := dm.db.QueryRow("SELECT uid FROM identity WHERE uid = $1", uid.String()).
		Scan(&id)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.Exists(uid)
		}
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (dm *DatabaseManagerSqlite) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	var privateKey []byte

	err := dm.db.QueryRow("SELECT private_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&privateKey)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.GetPrivateKey(uid)
		}
		return nil, err
	}

	return privateKey, nil
}

func (dm *DatabaseManagerSqlite) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	var publicKey []byte

	err := dm.db.QueryRow("SELECT public_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&publicKey)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.GetPublicKey(uid)
		}
		return nil, err
	}

	return publicKey, nil
}

func (dm *DatabaseManagerSqlite) GetAuthToken(uid uuid.UUID) (string, error) {
	var authToken string

	err := dm.db.QueryRow("SELECT auth_token FROM identity WHERE uid = $1", uid.String()).
		Scan(&authToken)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.GetAuthToken(uid)
		}
		return "", err
	}

	return authToken, nil
}

func (dm *DatabaseManagerSqlite) StartTransaction(ctx context.Context) (transactionCtx interface{}, err error) {
	return dm.db.BeginTx(ctx, dm.options)
}

// StartTransactionWithLock starts a transaction and acquires a lock on the row with the specified uuid as key.
// Returns error if row does not exist.
func (dm *DatabaseManagerSqlite) StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	var id string

	// lock row FOR UPDATE
	err = tx.QueryRow("SELECT uid FROM identity WHERE uid = $1", uid).
		Scan(&id)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.StartTransactionWithLock(ctx, uid)
		}
		return nil, err
	}

	return tx, nil
}

func (dm *DatabaseManagerSqlite) CloseTransaction(transactionCtx interface{}, commit bool) error {
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

func (dm *DatabaseManagerSqlite) FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	var id ent.Identity

	err := tx.QueryRow("SELECT * FROM identity WHERE uid = $1", uid.String()).
		Scan(&id.Uid, &id.PrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.FetchIdentity(tx, uid)
		}
		return nil, err
	}

	return &id, nil
}

func (dm *DatabaseManagerSqlite) SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	_, err := tx.Exec(
		"UPDATE identity SET signature = $1 WHERE uid = $2;",
		&signature, uid.String())
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.SetSignature(tx, uid, signature)
		}
		return err
	}

	return nil
}

func (dm *DatabaseManagerSqlite) StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	// make sure identity does not exist yet
	var id string

	err := tx.QueryRow("SELECT uid FROM identity WHERE uid = $1", identity.Uid).
		Scan(&id)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.StoreNewIdentity(tx, identity)
		}
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
		} else {
			return err
		}
	} else {
		return ErrExists
	}

	return dm.storeIdentity(tx, identity)
}

func (dm *DatabaseManagerSqlite) storeIdentity(tx *sql.Tx, identity *ent.Identity) error {
	_, err := tx.Exec(
		"INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		&identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		if IsConnectionAvailableErrorSqlite(err) {
			return dm.storeIdentity(tx, identity)
		}
		return err
	}

	return nil
}

func IsConnectionAvailableErrorSqlite(err error) bool {
	if err == sqlite3.ErrLocked {
		//time.Sleep(100 * time.Millisecond)
		//return true
	}
	return false
}
