package repository

import (
	"context"
	"database/sql"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

func MigrateToSqlite(c config.Config) error {
	txCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbManager, err := NewSqliteDatabaseInfo(c)
	if err != nil {
		return err
	}

	tx, shouldMigrate, err := checkVersionSqlite(txCtx, dbManager)
	if err != nil {
		return err
	}
	if !shouldMigrate {
		log.Infof("database migration version already up to date")
		return nil
	}

	log.Println("database migration version updated, ready to upgrade")
	identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
	if err != nil {
		return err
	}

	if _, err := dbManager.db.Exec(CREATE[SQLiteIdentity]); err != nil {
		return err
	}

	err = migrateIdentitiesSqlite(c, dbManager, identitiesToPort)
	if err != nil {
		return err
	}

	log.Infof("successfully migrated file based context into database")
	return updateVersion(tx)
}

func migrateIdentitiesSqlite(c config.Config, dm *DatabaseManagerSqlite, identities []ent.Identity) error {
	log.Infof("starting migration...")

	p, err := NewExtendedProtocol(dm, c.SecretBytes32, nil)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return err
	}

	for i, id := range identities {
		log.Infof("%4d: %s", i+1, id.Uid)

		err = p.StoreNewIdentity(tx, &id)
		if err != nil {
			if err == ErrExists {
				log.Warnf("%s: %v -> skip", id.Uid, err)
			} else {
				return err
			}
		}
	}

	return tx.Commit()
}

func checkVersionSqlite(ctx context.Context, dm *DatabaseManagerSqlite) (*sql.Tx, bool, error) {
	var version Migration

	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, false, err
	}

	if _, err := dm.db.Exec(CREATE[PostgresVersion]); err != nil {
		return tx, false, err
	}

	err = tx.QueryRow("SELECT * FROM version WHERE id = 'dbMigration'").
		Scan(&version.Id, &version.MigrationVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			shouldMigrate, err := CreateVersionEntry(tx, version)
			return tx, shouldMigrate, err
		} else {
			return tx, false, err
		}
	}
	log.Debugf("database migration version: %s / application migration version: %s", version.MigrationVersion, MigrationVersion)
	if version.MigrationVersion != MigrationVersion {
		return tx, true, nil
	}
	return tx, false, nil
}
