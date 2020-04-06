package main

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io/ioutil"
	"log"
	"os"

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

// Close prevents new queries to open, and blocks until the running queries are finished.
func (db *Postgres) Close() error {
	if db == nil {
		return nil
	}

	return db.conn.Close()
}

type FileStore struct {
	FilePath string
}

func (fs *FileStore) SetProtocolContext(proto driver.Valuer) error {
	err := os.Rename(fs.FilePath, fs.FilePath+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}

	// XXX
	value, err := proto.Value()
	if err != nil {
		return errors.New("Unable to serialize ProtocolContext")
	}

	if contextBytes, ok := value.([]byte); ok {
		return ioutil.WriteFile(fs.FilePath, contextBytes, 444)
	}

	return errors.New("Unable to serialize ProtocolContext")
}

func (fs *FileStore) GetProtocolContext(proto sql.Scanner) error {
	contextBytes, err := ioutil.ReadFile(fs.FilePath)
	if err != nil {
		file := fs.FilePath + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}

	return proto.Scan(contextBytes)
}

func (fs *FileStore) Close() error {
	return nil
}
