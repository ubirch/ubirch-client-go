package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

const (
	PostgresIdentity = iota
	PostgresVersion
	PostgresIdentityTableName = "identity"
	PostgresVersionTableName  = "version"
	MigrationID               = "dbMigration"
	MigrationVersion          = "1.0.1"
)

type Migration struct {
	Id      string
	Version string
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
}

func CreateTable(tableType int, tableName string) string {
	return fmt.Sprintf(create[tableType], tableName)
}

func Migrate(c config.Config) error {
	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, PostgresIdentityTableName, 3)
	if err != nil {
		return err
	}

	txCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	migration := &Migration{
		Id: MigrationID,
	}

	tx, err := getVersion(txCtx, dm, migration)
	if err != nil {
		return err
	}

	if migration.Version == MigrationVersion {
		log.Infof("database migration version already up to date")
		return nil
	}
	log.Debugf("database migration version: %s / application migration version: %s", migration.Version, MigrationVersion)

	p, err := NewExtendedProtocol(dm, c.SecretBytes32)
	if err != nil {
		return err
	}

	if strings.HasPrefix(migration.Version, "0.") {
		// migrate from file based context
		identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
		if err != nil {
			return err
		}

		err = migrateIdentities(p, identitiesToPort)
		if err != nil {
			return err
		}

		log.Infof("successfully migrated file based context into database")
	}

	//if strings.HasPrefix(migration.Version, "1.") {
	//	err = hashAuthTokens(dm, p)
	//	if err != nil {
	//		return err
	//	}
	//
	//	log.Infof("successfully hashed auth tokens in database")
	//}

	migration.Version = MigrationVersion
	return updateVersion(tx, migration)
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

func migrateIdentities(p *ExtendedProtocol, identities []ent.Identity) error {
	log.Infof("starting migration...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
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

		err = p.StoreNewIdentity(tx, id)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

//func hashAuthTokens(dm *DatabaseManager, p *ExtendedProtocol) error {
//	query := fmt.Sprintf("SELECT uid, auth_token FROM %s FOR UPDATE", dm.tableName)
//
//	rows, err := dm.db.Query(query)
//	if err != nil {
//		return err
//	}
//	defer func(rows *sql.Rows) {
//		err := rows.Close()
//		if err != nil {
//			log.Error(err)
//		}
//	}(rows)
//
//	var (
//		uid  uuid.UUID
//		auth string
//	)
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	tx, err := dm.db.BeginTx(ctx, dm.options)
//	if err != nil {
//		return err
//	}
//
//	for rows.Next() {
//		err = rows.Scan(&uid, &auth)
//		if err != nil {
//			return err
//		}
//
//		pwHash, err = p.PwHasher.GeneratePasswordHash(ctx, auth, p.PwHasherParams)
//		if err != nil {
//			return err
//		}
//
//		err = dm.StoreAuth(tx, uid, pwHash)
//		if err != nil {
//			return err
//		}
//	}
//	if rows.Err() != nil {
//		return rows.Err()
//	}
//
//	return tx.Commit()
//}

func getVersion(ctx context.Context, dm *DatabaseManager, migration *Migration) (*sql.Tx, error) {
	_, err := dm.db.Exec(CreateTable(PostgresVersion, PostgresVersionTableName))
	if err != nil {
		return nil, err
	}

	tx, err := dm.db.BeginTx(ctx, dm.options)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT migration_version FROM %s WHERE id = $1 FOR UPDATE", PostgresVersionTableName)

	err = tx.QueryRow(query, migration.Id).
		Scan(&migration.Version)
	if err != nil {
		if err == sql.ErrNoRows {
			migration.Version = "0.0"
			return tx, createVersionEntry(tx, migration)
		} else {
			return nil, fmt.Errorf("could not select version table entry %s: %v", migration.Id, err)
		}
	}
	return tx, nil
}

func createVersionEntry(tx *sql.Tx, migration *Migration) error {
	query := fmt.Sprintf("INSERT INTO %s (id, migration_version) VALUES ($1, $2);", PostgresVersionTableName)
	_, err := tx.Exec(query,
		&migration.Id, migration.Version)
	if err != nil {
		return fmt.Errorf("could not create version table entry %s with version %s: %v", migration.Id, migration.Version, err)
	}
	return nil
}

func updateVersion(tx *sql.Tx, migration *Migration) error {
	query := fmt.Sprintf("UPDATE %s SET migration_version = $1 WHERE id = $2;", PostgresVersionTableName)
	_, err := tx.Exec(query,
		migration.Version, &migration.Id)
	if err != nil {
		return fmt.Errorf("could not update version table entry %s to version %s: %v", migration.Id, migration.Version, err)
	}
	return tx.Commit()
}
