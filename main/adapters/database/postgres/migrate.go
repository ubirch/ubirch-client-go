package postgres

import (
	"embed"
	"net/http"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/jackc/pgx/v4"

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

func getMigrator(pgxConn *pgx.Conn) *migrate.Migrate {
	sourceInstance, err := httpfs.New(http.FS(migrations), "migrations")
	if err != nil {
		log.Fatalf("could not create new migrate source driver: %v", err)
	}

	// FIXME: extract connection info from existing connection,
	//  instead of re-using the connection.
	dsn := pgxConn.Config().ConnString()

	migrator, err := migrate.NewWithSourceInstance("httpfs", sourceInstance, dsn)
	if err != nil {
		log.Fatalf("could not create migrator: %v", err)
	}

	migrator.Log = &Log{}
	return migrator
}

func MigrateUp(pgxConn *pgx.Conn) {
	migrator := getMigrator(pgxConn)

	err := migrator.Up()
	if err == migrate.ErrNoChange {
		version, dirty, err := migrator.Version()
		if dirty {
			log.Fatalf("database schema is dirty, needs to be manually fixed. Schema version: %d", version)
		}
		if err != nil {
			log.Fatalf("database is migrated, but could not fetch schema version information. Error: %s", err)
		}
		// this is fine.
		log.Infof("nothing to migrate. Schema is already at version: %d", version)
		return
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
				log.Fatalf("forcing schema version to %d failed: %v", lastCleanVersion, err)
			}
		} else {
			log.Fatalf("unable to fix schema version after failed migration. Version: %d, Dirty: %v, Error: %v", version, dirty, errVersion)
		}

		log.Fatalf("database migration failed for version %d", version)
	}
	version, _, _ := migrator.Version()
	log.Infof("database schema was migrated. New schema version: %d", version)

}

func Migrate(pgxConn *pgx.Conn, targetVersion uint) {
	migrator := getMigrator(pgxConn)

	err := migrator.Migrate(targetVersion)
	if err == migrate.ErrNoChange {
		version, dirty, err := migrator.Version()
		if dirty {
			log.Fatalf("database schema is dirty, needs to be manually fixed. Schema version: %d", version)
		}
		if err != nil {
			log.Fatalf("database is migrated, but could not fetch schema version information. Error: %s", err)
		}
		// this is fine.
		log.Infof("nothing to migrate. Schema is already at version: %d", version)
		return
	} else if err != nil {
		log.Fatalf("could not migrate database. Error: %s", err)
	}
	version, _, _ := migrator.Version()
	log.Infof("database schema was migrated. New schema version: %d", version)

}
