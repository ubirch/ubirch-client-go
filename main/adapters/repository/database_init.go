package repository

import (
	"context"
	"database/sql"
	"fmt"
)

const (
	PostgresIdentity = iota
	PostgresVersion
	PostgresIdentityTableName = "identity"
	PostgresVersionTableName  = "version"
	MigrationID               = "dbMigration"
	MigrationVersion          = "2.0"
)

type Migration struct {
	Id      string
	Version string
}

var create = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
	PostgresVersion: "CREATE TABLE IF NOT EXISTS %s(" +
		"id VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"migration_version VARCHAR(255) NOT NULL);",
}

func (dm *DatabaseManager) CreateTable(tableType int, tableName string) error {
	query := fmt.Sprintf(create[tableType], tableName)
	_, err := dm.db.Exec(query)
	return err
}

func getVersion(ctx context.Context, dm *DatabaseManager, migration *Migration) (*sql.Tx, error) {
	err := dm.CreateTable(PostgresVersion, PostgresVersionTableName)
	if err != nil {
		return nil, err
	}

	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1 FOR UPDATE", PostgresVersionTableName)

	err = tx.QueryRow(query, migration.Id).
		Scan(&migration.Version)
	if err != nil {
		if err == sql.ErrNoRows {
			migration.Version = "0.0"
			return tx, createVersionEntry(tx, migration)
		} else {
			return nil, fmt.Errorf("could not select version table entry %s: %v", migration.Id, err)
		}
	}
	return tx, nil
}

func createVersionEntry(tx *sql.Tx, migration *Migration) error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", PostgresVersionTableName)
	_, err := tx.Exec(query,
		&migration.Id, migration.Version)
	if err != nil {
		return fmt.Errorf("could not create version table entry %s with version %s: %v", migration.Id, migration.Version, err)
	}
	return nil
}

func updateVersion(tx *sql.Tx, migration *Migration) error {
	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", PostgresVersionTableName)
	_, err := tx.Exec(query,
		migration.Version, &migration.Id)
	if err != nil {
		return fmt.Errorf("could not update version table entry %s to version %s: %v", migration.Id, migration.Version, err)
	}
	return tx.Commit()
}
