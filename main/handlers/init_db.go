package handlers

import (
	"context"
	"database/sql"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"os"
)

const MigrationVersion = "1.0"

const (
	PostgresIdentity = iota
	PostgresVersion
	//MySQL
	//SQLite
)

type Migration struct {
	Id               string
	MigrationVersion string
}

var CREATE = map[int]string{
	PostgresIdentity: "CREATE TABLE " + vars.PostgreSqlIdentityTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
	PostgresVersion: "CREATE TABLE " + vars.PostgreSqlVersionTableName + "(" +
		"id VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"migration_version VARCHAR(255) NOT NULL);",
	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
	//SQLite:   "CREATE TABLE identity (id INTEGER, datetime TEXT)",
}

type Table struct {
	exists bool
}

func Migrate(c config.Config) error {
	txCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbManager, err := NewSqlDatabaseInfo(c)
	if err != nil {
		return err
	}

	tx, shouldMigrate, err := checkVersion(txCtx, dbManager)
	if err != nil {
		return err
	}
	if !shouldMigrate {
		return nil
	}

	identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
	if err != nil {
		return err
	}

	err = checkForTable(dbManager, vars.PostgreSqlIdentityTableName, PostgresIdentity)
	if err != nil {
		return err
	}

	err = migrateIdentities(c, dbManager, identitiesToPort)
	if err != nil {
		return err
	}

	return updateVersion(tx)
}

func getAllIdentitiesFromLegacyCtx(c config.Config) ([]ent.Identity, error) {
	log.Infof("getting existing identities from file system")

	fileManager, err := NewFileManager(c.ConfigDir, c.SecretBytes16)
	if err != nil {
		return nil, err
	}

	uids, err := fileManager.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}

	var allIdentities []ent.Identity

	for _, uid := range uids {

		i := ent.Identity{
			Uid: uid.String(),
		}

		i.PrivateKey, err = fileManager.GetPrivateKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.PublicKey, err = fileManager.GetPublicKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.Signature, err = fileManager.GetSignature(uid)
		if err != nil {
			if os.IsNotExist(err) { // if file does not exist -> create genesis signature
				i.Signature = make([]byte, 64)
			} else { // file exists but something went wrong
				return nil, fmt.Errorf("%s: %v", uid, err)
			}
		}

		i.AuthToken, err = fileManager.GetAuthToken(uid)
		if err != nil {
			if os.IsNotExist(err) { // if file does not exist -> get auth token from config
				i.AuthToken = c.Devices[uid.String()]
			} else { // file exists but something went wrong
				return nil, fmt.Errorf("%s: %v", uid, err)
			}
		}

		allIdentities = append(allIdentities, i)
	}

	return allIdentities, nil
}

// TODO: check if there is not an more elegant way of checking for tables
func checkForTable(dm *DatabaseManager, tableName string, tableKey int) error {

	var table Table
	query := fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", tableName)

	if err := dm.db.QueryRow(query).Scan(&table.exists); err != nil {
		return fmt.Errorf("scan rows error: %v", err)
	}
	if !table.exists {
		log.Printf("database table %s doesn't exist creating table", tableName)
		if _, err := dm.db.Exec(CREATE[tableKey]); err != nil {
			return err
		}
	}
	return nil
}

func migrateIdentities(c config.Config, dm *DatabaseManager, identities []ent.Identity) error {
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

func checkVersion(ctx context.Context, dm *DatabaseManager) (*sql.Tx, bool, error) {
	var version Migration

	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, false, err
	}

	err = checkForTable(dm, vars.PostgreSqlIdentityTableName, PostgresVersion)
	if err != nil {
		return tx, false, err
	}

	err = tx.QueryRow("SELECT * FROM version WHERE id = 'dbMigration' FOR UPDATE").
		Scan(version.Id, &version.MigrationVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			shouldMigrate, err := CreateVersionEntry(tx, version)
			return tx, shouldMigrate, err
		} else {
			return tx, false, err
		}
	}
	if version.MigrationVersion != MigrationVersion {
		return tx, true, nil
	}
	return tx, false, nil
}

func CreateVersionEntry(tx *sql.Tx, version Migration) (bool, error) {
	version.Id = "dbMigration"
	version.MigrationVersion = MigrationVersion
	_, err := tx.Exec("INSERT INTO version (id, migration_version) VALUES ($1, $2);",
		&version.Id, version.MigrationVersion)
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
