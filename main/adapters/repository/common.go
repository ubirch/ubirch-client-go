package repository

import (
	"database/sql"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/vars"
)

const (
	PostgresIdentity = iota
	PostgresVersion
	SQLiteIdentity
	SQLiteVersion
	//MySQL
)

type Migration struct {
	Id               string
	MigrationVersion string
}

var CREATE = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS " + vars.SqlIdentityTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
	PostgresVersion: "CREATE TABLE IF NOT EXISTS " + vars.SqlVersionTableName + "(" +
		"id VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"migration_version VARCHAR(255) NOT NULL);",

	SQLiteIdentity: "CREATE TABLE IF NOT EXISTS " + vars.SqlIdentityTableName + "(" +
		"uid TEXT NOT NULL PRIMARY KEY, " +
		"private_key BLOB NOT NULL, " +
		"public_key BLOB NOT NULL, " +
		"signature BLOB NOT NULL, " +
		"auth_token TEXT NOT NULL);",
	SQLiteVersion: "CREATE TABLE IF NOT EXISTS " + vars.SqlVersionTableName + "(" +
		"id TEXT NOT NULL PRIMARY KEY, " +
		"migration_version TEXT NOT NULL);",
	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
}

func Migrate(c config.Config) error {
	if c.DsnType == vars.Sqlite {
		return MigrateToSqlite(c)
	}
	return MigrateToPostgres(c)
}

func CreateVersionEntry(tx *sql.Tx, version Migration) (bool, error) {
	version.Id = "dbMigration"
	version.MigrationVersion = MigrationVersion
	_, err := tx.Exec("INSERT INTO version (id, migration_version) VALUES ($1, $2);",
		&version.Id, &version.MigrationVersion)
	if err != nil {
		return false, err
	}
	return true, nil
}

func updateVersion(tx *sql.Tx) error {
	var version Migration
	version.Id = "dbMigration"
	version.MigrationVersion = MigrationVersion
	_, err := tx.Exec("UPDATE version SET migration_version = $1 WHERE id = $2;",
		&version.MigrationVersion, &version.Id)
	if err != nil {
		return err
	}
	return tx.Commit()
}
