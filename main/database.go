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

package main

import (
	"database/sql"
	"database/sql/driver"
	"fmt"

	"github.com/google/uuid"
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

// Postgres contains the postgres database connection, and offers methods
// for interacting with the database.
type Postgres struct {
	conn              *sql.DB
	EncryptedKeystore *ubirch.EncryptedKeystore
}

func (db *Postgres) StartTransaction(uid uuid.UUID) error {
	panic("implement me")
}

func (db *Postgres) EndTransaction(uid uuid.UUID, success bool) error {
	panic("implement me")
}

func (db *Postgres) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

func (db *Postgres) SetPrivateKey(uid uuid.UUID, key []byte) error {
	panic("implement me")
}

func (db *Postgres) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

func (db *Postgres) SetPublicKey(uid uuid.UUID, key []byte) error {
	panic("implement me")
}

func (db *Postgres) GetSignature(uid uuid.UUID) ([]byte, error) {
	panic("implement me")
}

func (db *Postgres) SetSignature(uid uuid.UUID, signature []byte) error {
	panic("implement me")
}

func (db *Postgres) GetAuthToken(uid uuid.UUID) (string, error) {
	panic("implement me")
}

func (db *Postgres) SetAuthToken(uid uuid.UUID, authToken string) error {
	panic("implement me")
}

// Ensure Postgres implements the ContextManager interface
var _ ContextManager = (*Postgres)(nil)

// NewPostgres takes a database connection string, returns a new initialized
// database.
func NewPostgres(dsn string, secret []byte) (*Postgres, error) {
	// FIXME: use the database
	return nil, fmt.Errorf("database currently not supported")

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	log.Print("Initialized database connection")

	return &Postgres{
		conn:              db,
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
	}, nil
}

// SetProtocolContext stores the current protocol context.
// If the operation failed, a Database error will be returned.
func (db *Postgres) SetProtocolContext(proto driver.Valuer) error {
	const query = `
		INSERT INTO "protocol_context" ("id", "json")
		VALUES (1, $1)
		ON CONFLICT ("id")
			DO UPDATE SET "json" = $1;`

	_, err := db.conn.Exec(query, proto)

	return err
}

// GetProtocolContext retrieves the current protocol context.
// If the operation failed, a Database error will be returned.
func (db *Postgres) GetProtocolContext(proto sql.Scanner) error {
	const query = `
		SELECT "json"
		FROM "protocol_context"
		WHERE "id" = 1;`

	err := db.conn.QueryRow(query).Scan(proto)
	return err
}

// Close prevents new queries to open, and blocks until the running queries are finished.
func (db *Postgres) Close() error {
	return db.conn.Close()
}
