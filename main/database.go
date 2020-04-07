package main

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"

	"log"

	// postgres driver is imported for side effects
	_ "github.com/lib/pq"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

// Database is the interface that defines what methods a database has to
// implement.
type Database interface {
	SetProtocolContext(proto driver.Valuer) error
	GetProtocolContext(proto sql.Scanner) error

	PersistLastSignature(clientUUID string, signature []byte) error
	PersistKeystore(ubirch.Keystorer) error

	Close() error
}

// Postgres contains the postgres database connection, and offers methods
// for interacting with the database.
type Postgres struct {
	conn *sql.DB
}

// NewPostgres takes a database connection string, returns a new initialized
// database.
func NewPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	log.Print("Initialized database connection")

	return &Postgres{conn: db}, nil
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

func (db *Postgres) persistKeystore(keystore driver.Valuer) error {
	const query = `
		INSERT INTO "keystore" ("id", "json")
		VALUES (1, $1)
		ON CONFLICT ("id")
			DO UPDATE SET "json" = $1;`
	_, err := db.conn.Exec(query, keystore)
	return err
}

func (db *Postgres) persistLastSignature(clientUUID string, bytes []byte) error {
	const query = `
		INSERT INTO "last_signature" ("client_uuid", "signature")
		VALUES ($1, $2)
		ON CONFLICT ("client_uuid")
		DO UPDATE SET "signature" = $2;`
	_, err := db.conn.Exec(query, clientUUID, bytes)
	return err
}

// Close prevents new queries to open, and blocks until the running queries are finished.
func (db *Postgres) Close() error {
	if db == nil {
		return nil
	}

	return db.conn.Close()
}

// databaseJSONWrapper is a small helper which lets all json-serializable objects
// also implement the sql.Scanner and driver.Valuer interfaces, for easy
// (de)serialization in SQL databases.
type databaseJSONWrapper struct {
	Object json.Marshaler
}

// Value lets the struct implement the driver.Valuer interface. This method
// simply returns the JSON-encoded representation of the struct.
func (j databaseJSONWrapper) Value() (driver.Value, error) {
	return json.Marshal(j.Object)
}

// Scan lets the struct implement the sql.Scanner interface. This method
// simply decodes a JSON-encoded value into the struct fields.
func (j *databaseJSONWrapper) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(b, j.Object)
}
