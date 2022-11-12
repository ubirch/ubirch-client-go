package repository

import (
	"fmt"
)

const (
	PostgresIdentity = iota
	SQLiteIdentity

	IdentityTableName = "identity"
)

var create = map[int]string{
	PostgresIdentity: fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"private_key BYTEA NOT NULL, "+
		"public_key BYTEA NOT NULL, "+
		"signature BYTEA NOT NULL, "+
		"auth_token VARCHAR(255) NOT NULL, "+
		"active boolean NOT NULL DEFAULT(TRUE));", IdentityTableName),

	SQLiteIdentity: fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid TEXT NOT NULL PRIMARY KEY, "+
		"private_key BLOB NOT NULL, "+
		"public_key BLOB NOT NULL, "+
		"signature BLOB NOT NULL, "+
		"auth_token TEXT NOT NULL, "+
		"active INTEGER NOT NULL DEFAULT(TRUE));", IdentityTableName),
}

func (dm *DatabaseManager) CreateTable(tableType int) error {
	_, err := dm.db.Exec(create[tableType])
	return err
}
