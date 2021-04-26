package handlers

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/keystr"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"log"
)

const (
	Postgres = iota
	//MySQL
	//SQLite
)

var CREATE = map[int]string{
	Postgres: "CREATE TABLE " + vars.PostgreSqlTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",

	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
	//SQLite:   "CREATE TABLE identity (id INTEGER, datetime TEXT)",
}

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
	options     *sql.TxOptions
	conn        string
	client      Client
	encKeyStore *keystr.EncryptedKeystore
}

type Table struct {
	exists bool
}
// Ensure Database implements the ContextManager interface
var _ ContextManager = (*DatabaseManager)(nil)

// NewSqlDatabaseInfo takes a database connection string, returns a new initialized
// database.
func NewSqlDatabaseInfo(dsn config.DSN, secret []byte) (*DatabaseManager, error) {
	dataSourceName := fmt.Sprintf("host=%s user=%s password=%s port=%d dbname=%s sslmode=disable",
		dsn.Host, dsn.User, dsn.Password, vars.PostgreSqlPort, dsn.Db)

	log.Print("preparing postgres usage")

	if err := checkForTable(dataSourceName); err != nil {
		log.Panicf("could not create missing table in database: %v", err)
	}

	return &DatabaseManager{
		options: &sql.TxOptions{
			Isolation: sql.LevelRepeatableRead,
			ReadOnly:  false,
		},
		conn:        dataSourceName,
		encKeyStore: keystr.NewEncryptedKeystore(secret)}, nil
}

func checkForTable(dsn string) error {
	pg, err := sql.Open(vars.PostgreSql, dsn)
	if err != nil {
		return err
	}
	defer pg.Close()
	if err = pg.Ping(); err != nil {
		return err
	}

	query := fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", vars.PostgreSqlTableName)
	row, err := pg.Query(query)
	if err != nil {
		return err
	}
	if row.Next() {
		var table Table
		err := row.Scan(&table.exists)
		if err != nil {
			return fmt.Errorf("scan rows error: %v", err)
		}
		if !table.exists {
			log.Printf("database table %s doesn't exist creating table",vars.PostgreSqlTableName)
			if _, err = pg.Exec(CREATE[Postgres]); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("expected row not found")
	}
	return nil
}
