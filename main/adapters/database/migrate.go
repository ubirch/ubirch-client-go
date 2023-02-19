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

func getMigrator(driver string, db *sql.DB) (*migrate.Migrate, error) {
	var (
		sourceInstance source.Driver
		driverInstance database.Driver
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
		driverInstance, err = postgres.WithInstance(db, &postgres.Config{})
	case SQLite:
		driverInstance, err = sqlite.WithInstance(db, &sqlite.Config{NoTxWrap: true})
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}

	if err != nil {
		return nil, fmt.Errorf("could not create new migrate database driver: %v", err)
	}

	migrator, err := migrate.NewWithInstance("httpfs", sourceInstance, driver, driverInstance)
	if err != nil {
		return nil, fmt.Errorf("could not create migrator: %v", err)
	}

	migrator.Log = &Log{}
	return migrator, nil
}

func closeMigrator(migrator *migrate.Migrate) {
	sourceErr, databaseErr := migrator.Close()
	if sourceErr != nil || databaseErr != nil {
		log.Errorf("Error closing drivers: source: %v, database: %v", sourceErr, databaseErr)
	}
}

func checkMigrationError(migrator *migrate.Migrate, err error) error {
	if err == migrate.ErrNoChange {
		version, err := getVersion(migrator)
		if err != nil {
			return err
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

func getVersion(migrator *migrate.Migrate) (uint, error) {
	version, dirty, err := migrator.Version()
	if err == migrate.ErrNilVersion {
		return 0, err
	}
	if err != nil {
		return 0, fmt.Errorf("could not fetch database schema version information. Error: %s", err)
	}

	if dirty {
		return 0, fmt.Errorf("database schema is dirty, needs to be manually fixed. Schema version: %d", version)
	}

	return version, nil
}

func migrateUp(driver string, db *sql.DB) error {
	migrator, err := getMigrator(driver, db)
	if err != nil {
		return err
	}
	defer closeMigrator(migrator)

	err = migrator.Up()
	return checkMigrationError(migrator, err)
}

func migrateDown(driver string, db *sql.DB) error {
	migrator, err := getMigrator(driver, db)
	if err != nil {
		return err
	}
	defer closeMigrator(migrator)

	err = migrator.Down()
	return checkMigrationError(migrator, err)
}

func migrateTo(driver string, db *sql.DB, targetVersion uint) error {
	migrator, err := getMigrator(driver, db)
	if err != nil {
		return err
	}
	defer closeMigrator(migrator)

	err = migrator.Migrate(targetVersion)
	return checkMigrationError(migrator, err)
}
