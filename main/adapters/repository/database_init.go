package repository

import (
	"fmt"
)

const (
	IdentityTableName         = "identity"
	ExternalIdentityTableName = "external_identity"
)

var createPostgres = []string{
	fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"private_key BYTEA NOT NULL, "+
		"public_key BYTEA NOT NULL, "+
		"signature BYTEA NOT NULL, "+
		"auth_token VARCHAR(255) NOT NULL, "+
		"active boolean NOT NULL DEFAULT(TRUE));", IdentityTableName),

	fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, "+
		"public_key BYTEA NOT NULL);", ExternalIdentityTableName),
}

var createSQLite = []string{
	fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid TEXT NOT NULL PRIMARY KEY, "+
		"private_key BLOB NOT NULL, "+
		"public_key BLOB NOT NULL, "+
		"signature BLOB NOT NULL, "+
		"auth_token TEXT NOT NULL, "+
		"active INTEGER NOT NULL DEFAULT(TRUE));", IdentityTableName),

	fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s("+
		"uid TEXT NOT NULL PRIMARY KEY, "+
		"public_key BLOB NOT NULL);", ExternalIdentityTableName),
}

func (dm *DatabaseManager) CreateTables(createStatements []string) error {
	for _, create := range createStatements {
		_, err := dm.db.Exec(create)
		if err != nil {
			return err
		}
	}
	return nil
}
