package repository

import (
	"database/sql"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/vars"
)

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