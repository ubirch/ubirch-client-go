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
	id      string
	version string
	tx      *sql.Tx
}

var create = map[int]string{
	PostgresIdentity: fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"private_key BYTEA NOT NULL, "+
		"public_key BYTEA NOT NULL, "+
		"signature BYTEA NOT NULL, "+
		"auth_token VARCHAR(255) NOT NULL);", PostgresIdentityTableName),
	PostgresVersion: fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"id VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"migration_version VARCHAR(255) NOT NULL);", PostgresVersionTableName),
}

func (dm *DatabaseManager) CreateTable(tableType int) error {
	_, err := dm.db.Exec(create[tableType])
	return err
}

func (m *Migration) getVersion(ctx context.Context, dm *DatabaseManager) error {
	err := dm.CreateTable(PostgresVersion)
	if err != nil {
		return err
	}

	m.tx, err = dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return err
	}

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1 FOR UPDATE", PostgresVersionTableName)

	err = m.tx.QueryRow(query, m.id).
		Scan(&m.version)
	if err != nil {
		if err == sql.ErrNoRows {
			m.version = "0.0"
			return m.createVersionEntry()
		} else {
			return fmt.Errorf("could not select version table entry %s: %v", m.id, err)
		}
	}
	return nil
}

func (m *Migration) createVersionEntry() error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", PostgresVersionTableName)
	_, err := m.tx.Exec(query,
		&m.id, m.version)
	if err != nil {
		return fmt.Errorf("could not create version table entry %s with version %s: %v", m.id, m.version, err)
	}
	return nil
}

func (m *Migration) updateVersion() error {
	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", PostgresVersionTableName)
	_, err := m.tx.Exec(query,
		m.version, &m.id)
	if err != nil {
		return fmt.Errorf("could not update version table entry %s to version %s: %v", m.id, m.version, err)
	}
	return m.tx.Commit()
}
