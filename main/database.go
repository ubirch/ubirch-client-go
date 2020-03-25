package main

import (
	"database/sql"
	"database/sql/driver"
	"log"

	// postgres driver is imported for side effects
	_ "github.com/lib/pq"
)

// Database is the interface that defines what methods a database has to
// implement.
type Database interface {
	SetProtocolContext(proto driver.Valuer) error
	GetProtocolContext(proto sql.Scanner) error

	GetAuthKeysMaps() (authmap, keysmap map[string]string, err error)

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
		ON CONFLICT
			DO UPDATE SET "json" = $1 WHERE "id" = 1;`

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

// GetAuthKeysMaps retrieves the auth map and keys map from the auth list.
// If the operation failed, a Database error will be returned.
func (db *Postgres) GetAuthKeysMaps() (authmap, keysmap map[string]string, err error) {
	const query = `id
		SELECT "id", "key", "auth_token"
		FROM "auth"`

	rows, err := db.conn.Query(query)
	defer rows.Close()
	for rows.Next() {
		var id string
		var key string
		var authToken string

		err = rows.Scan(&id, &key, &authToken)
		if err != nil {
			return authmap, keysmap, err
		}

		authmap[id] = authToken
		keysmap[id] = key
	}

	return authmap, keysmap, rows.Err()
}

// Close prevents new queries to open, and blocks until the running queries are finished.
func (db *Postgres) Close() error {
	if db == nil {
		return nil
	}

	return db.conn.Close()
}
