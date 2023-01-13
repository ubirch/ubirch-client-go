package postgres

import (
	"database/sql"
	"embed"
	"fmt"
	"net/http"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/httpfs"

	log "github.com/sirupsen/logrus"
)

//go:embed migrations/*
var migrations embed.FS

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

func getMigrator(db *sql.DB) (*migrate.Migrate, error) {
	sourceInstance, err := httpfs.New(http.FS(migrations), "migrations")
	if err != nil {
		return nil, fmt.Errorf("could not create new migrate source driver: %v", err)
	}

	driverInstance, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not create new migrate database driver: %v", err)
	}

	migrator, err := migrate.NewWithInstance("httpfs", sourceInstance, "postgres", driverInstance)
	if err != nil {
		return nil, fmt.Errorf("could not create migrator: %v", err)
	}

	migrator.Log = &Log{}
	return migrator, nil
}

func MigrateUp(db *sql.DB) error {
	migrator, err := getMigrator(db)
	if err != nil {
		return err
	}

	err = migrator.Up()
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
		log.Errorf("could not migrate database. Error: %s", err)

		// since every migration step is executed within a transaction, changes will be rolled back
		// if something goes wrong. We can then safely set the schema version to the last clean version
		// and remove the dirty flag, which is set automatically if a migration step failed.
		version, dirty, errVersion := migrator.Version()
		if dirty && version > 0 {
			lastCleanVersion := int(version) - 1
			log.Infof("forcing from dirty schema version %d down to %d", version, lastCleanVersion)

			err := migrator.Force(lastCleanVersion)
			if err != nil {
				return fmt.Errorf("forcing schema version to %d failed: %v", lastCleanVersion, err)
			}
		} else {
			return fmt.Errorf("unable to fix schema version after failed migration. Version: %d, Dirty: %v, Error: %v", version, dirty, errVersion)
		}

		return fmt.Errorf("database migration failed for version %d", version)
	}
	version, _, _ := migrator.Version()
	log.Infof("database schema was migrated. New schema version: %d", version)

	return nil
}

func MigrateDown(db *sql.DB) error {
	migrator, err := getMigrator(db)
	if err != nil {
		return err
	}

	err = migrator.Down()
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

func Migrate(db *sql.DB, targetVersion uint) error {
	migrator, err := getMigrator(db)
	if err != nil {
		return err
	}

	err = migrator.Migrate(targetVersion)
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
