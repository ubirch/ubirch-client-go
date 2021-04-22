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

package todo

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"

	// postgres driver is imported for side effects
	_ "github.com/lib/pq"
)

// Database is the interface that defines what methods a database has to
// implement.
type Database interface {
	SetProtocolContext(proto driver.Valuer) error
	GetProtocolContext(proto sql.Scanner) error

	Close() error
}

// Database contains the postgres database connection, and offers methods
// for interacting with the database.
type DatabaseManager struct {
	conn        string
	client      Client
	encKeyStore *ubirch.EncryptedKeystore
}

func (dm *DatabaseManager) StartTransaction(uid uuid.UUID) error {
	panic("implement me")
}

func (dm *DatabaseManager) EndTransaction(uid uuid.UUID, success bool) error {
	panic("implement me")
}

func (dm *DatabaseManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	return dm.encKeyStore.GetPrivateKey(uid)
}

func (dm *DatabaseManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	return dm.encKeyStore.SetPrivateKey(uid, key)
}

func (dm *DatabaseManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	return dm.encKeyStore.GetPublicKey(uid)
}

func (dm *DatabaseManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	return dm.encKeyStore.SetPublicKey(uid, key)
}

func (dm *DatabaseManager) GetSignature(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

func (dm *DatabaseManager) SetSignature(uid uuid.UUID, signature []byte) error {
	panic("implement me")
}

func (dm *DatabaseManager) GetAuthToken(uid uuid.UUID) (string, error) {
	panic("implement me")
}

func (dm *DatabaseManager) SetAuthToken(uid uuid.UUID, authToken string) error {
	panic("implement me")
}

func (dm *DatabaseManager) Close() error {
	panic("implement me")
}

//func (s *DatabaseManager) GetAllIdentities() ([]ent.Identity, error) {
//	var ids []ent.Identity
//	pg, err := sql.Open(vars.PostgreSql, s.conn)
//	if err != nil {
//		return nil, err
//	}
//	defer pg.Close()
//	if err := pg.Ping(); err != nil {
//		log.Panic(fmt.Sprintf("pg can be pinged err: %v", err))
//	}
//	query := `ELECT * FROM weather WHERE city = 'San Francisco'`
//	rows, err := pg.Query(query)
//	if err != nil {
//		return nil, err
//	}
//
//	for rows.Next() {
//		var id ent.Identity
//		if err := rows.Scan(&id); err != nil {
//			return nil, err
//		}
//		ids = append(ids, id)
//	}
//
//	return ids, nil
//}

func (dm *DatabaseManager) FetchIdentity(ctx context.Context, uid uuid.UUID) (*ent.Identity, error) {
	pg, err := sql.Open(vars.PostgreSql, dm.conn)
	if err != nil {
		return nil, err
	}
	defer pg.Close()
	if err := pg.Ping(); err != nil {
		log.Panic(fmt.Sprintf("pg can be pinged err: %v", err))
	}
	query := `SELECT * FROM identity WHERE uui = %q`
	rows, err := pg.Query(fmt.Sprintf(query, uid))
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var id ent.Identity
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		return &id, nil
	}

	return nil, nil
}

func (dm *DatabaseManager) StoreIdentity(ctx context.Context, identity ent.Identity) error {
	db, err := sql.Open(vars.PostgreSql, dm.conn)
	if err != nil {
		return err
	}
	defer db.Close()

	query := fmt.Sprintf("INSERT INTO identity (uid, private_key, public_key, signature, auth_token)"+
		" VALUES (%s, %s, %s, %s, %s);", identity.Uid, identity.PrivateKey, identity.PublicKey,
		identity.Signature, identity.AuthToken)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dsn config.DSN, secret []byte) (*DatabaseManager, error) {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s port=%d dbname=%s sslmode=disable",
		dsn.Host, dsn.User, dsn.Password, vars.PostgreSqlPort, dsn.Db)

	log.Print("preparing postgres usage")

	return &DatabaseManager{conn: dataSourceName, encKeyStore: ubirch.NewEncryptedKeystore(secret)}, nil
}
