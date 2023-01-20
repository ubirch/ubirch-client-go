package database

import (
	"database/sql"
	"embed"
	"fmt"
	"net/http"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/httpfs"

	log "github.com/sirupsen/logrus"
)

//go:embed postgres/migrations/*
var postgresMigrations embed.FS

//go:embed sqlite/migrations/*
var sqliteMigrations embed.FS

// Log represents the logger for migrations
type Log struct {
	verbose bool
}

// Printf prints out formatted string into a log
func (l *Log) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Verbose shows if verbose print enabled
func (l *Log) Verbose() bool {
	return log.IsLevelEnabled(log.DebugLevel) || l.verbose
}

func getMigrator(db *sql.DB, driver string) (*migrate.Migrate, error) {
	var (
		sourceInstance source.Driver
		driverInstance database.Driver
		databaseName   string
		err            error
	)

	switch driver {
	case PostgreSQL:
		sourceInstance, err = httpfs.New(http.FS(postgresMigrations), "postgres/migrations")
	case SQLite:
		sourceInstance, err = httpfs.New(http.FS(sqliteMigrations), "sqlite/migrations")
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}

	if err != nil {
		return nil, fmt.Errorf("could not create new migrate source driver: %v", err)
	}

	switch driver {
	case PostgreSQL:
		databaseName = "postgres"
		driverInstance, err = postgres.WithInstance(db, &postgres.Config{})
	case SQLite:
		databaseName = "sqlite"
		driverInstance, err = sqlite.WithInstance(db, &sqlite.Config{NoTxWrap: true})
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}

	if err != nil {
		return nil, fmt.Errorf("could not create new migrate database driver: %v", err)
	}

	migrator, err := migrate.NewWithInstance("httpfs", sourceInstance, databaseName, driverInstance)
	if err != nil {
		return nil, fmt.Errorf("could not create migrator: %v", err)
	}

	migrator.Log = &Log{}
	return migrator, nil
}

func checkMigrationError(migrator *migrate.Migrate, err error) error {
	if err == migrate.ErrNoChange {
		version, dirty, err := migrator.Version()
		if dirty {
			return fmt.Errorf("database schema is dirty, needs to be manually fixed. Schema version: %d", version)
		}
		if err != nil {
			return fmt.Errorf("database is migrated, but could not fetch schema version information. Error: %s", err)
		}
		// this is fine.
		log.Infof("nothing to migrate. Schema is already at version: %d", version)
		return nil
	} else if err != nil {
		return fmt.Errorf("could not migrate database. Error: %s", err)
	}
	version, _, _ := migrator.Version()
	log.Infof("database schema was migrated. New schema version: %d", version)

	return nil
}

func migrateUp(db *sql.DB, driver string) error {
	migrator, err := getMigrator(db, driver)
	if err != nil {
		return err
	}

	err = migrator.Up()
	return checkMigrationError(migrator, err)
}

func migrateDown(db *sql.DB, driver string) error {
	migrator, err := getMigrator(db, driver)
	if err != nil {
		return err
	}

	err = migrator.Down()
	return checkMigrationError(migrator, err)
}

func migrateTo(db *sql.DB, driver string, targetVersion uint) error {
	migrator, err := getMigrator(db, driver)
	if err != nil {
		return err
	}

	err = migrator.Migrate(targetVersion)
	return checkMigrationError(migrator, err)
}
