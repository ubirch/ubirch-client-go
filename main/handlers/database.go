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

package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
	// postgres driver is imported for side effects
	_ "github.com/lib/pq"
)

// DatabaseManager contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	options *sql.TxOptions
	db      *sql.DB
	client  Client
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dsn config.DSN) (*DatabaseManager, error) {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s port=%d dbname=%s sslmode=disable",
		dsn.Host, dsn.User, dsn.Password, vars.PostgreSqlPort, dsn.Db)

	pg, err := sql.Open(vars.PostgreSql, dataSourceName)
	if err != nil {
		return nil, err
	}
	//pg.SetMaxOpenConns(100)
	//pg.SetMaxIdleConns(100)
	//pg.SetConnMaxLifetime(5*time.Minute)
	if err = pg.Ping(); err != nil {
		return nil, err
	}

	log.Print("preparing postgres usage")

	return &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
			ReadOnly:  false,
		},
		db: pg,
	}, nil
}

func (dm *DatabaseManager) Exists(uid uuid.UUID) (bool, error) {
	var id string

	err := dm.db.QueryRow("SELECT uid FROM identity WHERE uid = $1", uid.String()).
		Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	var privateKey []byte

	err := dm.db.QueryRow("SELECT private_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&privateKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	var publicKey []byte

	err := dm.db.QueryRow("SELECT public_key FROM identity WHERE uid = $1", uid.String()).
		Scan(&publicKey)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (string, error) {
	var authToken string

	err := dm.db.QueryRow("SELECT auth_token FROM identity WHERE uid = $1", uid.String()).
		Scan(&authToken)
	if err != nil {
		//if err.Error() == pq.ErrorCode("53300").Name() {
		//
		//}
		return "", err
	}

	return authToken, nil
}

func (dm *DatabaseManager) StartTransaction(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error) {
	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	var id string

	// lock row FOR UPDATE
	err = tx.QueryRow("SELECT uid FROM identity WHERE uid = $1 FOR UPDATE", uid).
		Scan(&id)
	if err != nil && err != sql.ErrNoRows {
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

func (dm *DatabaseManager) FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error) {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	var id ent.Identity

	err := tx.QueryRow("SELECT * FROM identity WHERE uid = $1", uid.String()).
		Scan(&id.Uid, &id.PrivateKey, &id.PublicKey, &id.Signature, &id.AuthToken)
	if err != nil {
		return nil, err
	}

	return &id, nil
}

func (dm *DatabaseManager) SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	_, err := tx.Exec(
		"UPDATE identity SET signature = $1 WHERE uid = $2;",
		&signature, uid.String())
	if err != nil {
		return err
	}

	return nil
}

func (dm *DatabaseManager) StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error {
	tx, ok := transactionCtx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("transactionCtx for database manager is not of expected type *sql.Tx")
	}

	// make sure identity does not exist yet
	var id string

	err := tx.QueryRow("SELECT uid FROM identity WHERE uid = $1 FOR UPDATE", identity.Uid).
		Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
		} else {
			return err
		}
	} else {
		return fmt.Errorf("entry not unique, uuid already exits %s", identity.Uid)
	}

	return dm.storeIdentity(tx, identity)
}

func (dm *DatabaseManager) storeIdentity(tx *sql.Tx, identity *ent.Identity) error {
	_, err := tx.Exec(
		"INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		&identity.Uid, &identity.PrivateKey, &identity.PublicKey, &identity.Signature, &identity.AuthToken)
	if err != nil {
		return err
	}

	return nil
}
