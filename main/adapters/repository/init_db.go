package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

const MigrationVersion = "1.0.1"

const (
	PostgresIdentity = iota
	PostgresVersion
	PostgreSqlIdentityTableName string = "identity"
	PostgreSqlVersionTableName  string = "version"
)

type Migration struct {
	Id               string
	MigrationVersion string
}

var create = map[int]string{
	PostgresIdentity: "CREATE TABLE IF NOT EXISTS %s(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",
	PostgresVersion: "CREATE TABLE IF NOT EXISTS %s(" +
		"id VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"migration_version VARCHAR(255) NOT NULL);",
	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
	//SQLite:   "CREATE TABLE identity (id INTEGER, datetime TEXT)",
}

func CreateTable(tableType int, tableName string) string {
	return fmt.Sprintf(create[tableType], tableName)
}

func Migrate(c config.Config) error {
	txCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbManager, err := NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName)
	if err != nil {
		return err
	}

	tx, shouldMigrate, err := checkVersion(txCtx, dbManager)
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

	err = migrateIdentities(c, dbManager, identitiesToPort)
	if err != nil {
		return err
	}

	log.Infof("successfully migrated file based context into database")
	return updateVersion(tx)
}

func getAllIdentitiesFromLegacyCtx(c config.Config) ([]ent.Identity, error) {
	log.Infof("getting existing identities from file system")

	secret16Bytes, err := base64.StdEncoding.DecodeString(c.Secret16Base64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 encoded secret for legacy key store decoding (%s): %v", c.Secret16Base64, err)
	}
	if len(secret16Bytes) != 16 {
		return nil, fmt.Errorf("invalid secret for legacy key store decoding: secret length must be 16 bytes (is %d)", len(secret16Bytes))
	}

	fileManager, err := NewFileManager(c.ConfigDir, secret16Bytes)
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
			Uid: uid,
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

		initialized, err := p.IsInitialized(id.Uid)
		if err != nil {
			return err
		}

		if initialized {
			log.Warnf("skipping %s: already initialized", id.Uid)
			continue
		}

		err = p.StoreNewIdentity(tx, &id)
		if err != nil {
			return err
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

	if _, err := dm.db.Exec(CreateTable(PostgresVersion, PostgreSqlVersionTableName)); err != nil {
		return tx, false, err
	}

	err = tx.QueryRow("SELECT * FROM version WHERE id = 'dbMigration' FOR UPDATE").
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
