package handlers

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/keystr"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"os"
)

const (
	Postgres = iota
	//MySQL
	//SQLite
)

var CREATE = map[int]string{
	Postgres: "CREATE TABLE " + vars.PostgreSqlTableName + "(" +
		"uid VARCHAR(255) NOT NULL PRIMARY KEY, " +
		"private_key BYTEA NOT NULL, " +
		"public_key BYTEA NOT NULL, " +
		"signature BYTEA NOT NULL, " +
		"auth_token VARCHAR(255) NOT NULL);",

	//MySQL:    "CREATE TABLE identity (id INT, datetime TIMESTAMP)",
	//SQLite:   "CREATE TABLE identity (id INTEGER, datetime TEXT)",
}

type Table struct {
	exists bool
}

func Migrate(c config.Config) error {
	identitiesToPort, err := getAllIdentitiesFromLegacyCtx(c)
	if err != nil {
		return err
	}
	// todo ^^^ port these identities ^^^

	dbManager, err := NewSqlDatabaseInfo(c)
	if err != nil {
		return err
	}
	checkForTable(dbManager)
}

func getAllIdentitiesFromLegacyCtx(c config.Config) (*[]ent.Identity, error) {
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

		priv, err := fileManager.GetPrivateKey(uid)
		if err != nil {
			return nil, err
		}

		pub, err := fileManager.GetPublicKey(uid)
		if err != nil {
			return nil, err
		}

		sign, err := fileManager.GetSignature(uid)
		if err != nil {
			if !os.IsNotExist(err) { // file exists but something went wrong
				return nil, err
			} else { // if file does not exist -> create genesis signature
				sign = make([]byte, 64)
			}
		}

		auth, err := fileManager.GetAuthToken(uid)
		if !os.IsNotExist(err) { // file exists but something went wrong
			return nil, err
		} else { // if file does not exist -> get auth token from config
			auth = c.Devices[uid.String()]
		}

		i := ent.Identity{
			Uid:        uid.String(),
			PrivateKey: priv,
			PublicKey:  pub,
			Signature:  sign,
			AuthToken:  auth,
		}

		allIdentities = append(allIdentities, i)
	}

	return &allIdentities, nil
}

func checkForTable(dm *DatabaseManager) error {
	pg, err := sql.Open(vars.PostgreSql, dm.conn)
	if err != nil {
		return err
	}
	defer pg.Close()
	if err = pg.Ping(); err != nil {
		return err
	}

	query := fmt.Sprintf("SELECT to_regclass('%s') IS NOT NULL", vars.PostgreSqlTableName)
	row, err := pg.Query(query)
	if err != nil {
		return err
	}
	if row.Next() {
		var table Table
		err := row.Scan(&table.exists)
		if err != nil {
			return fmt.Errorf("scan rows error: %v", err)
		}
		if !table.exists {
			log.Printf("database table %s doesn't exist creating table", vars.PostgreSqlTableName)
			if _, err = pg.Exec(CREATE[Postgres]); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("expected row not found")
	}
	return nil
}

func migrateIdentities(c config.Config, dsn string) error {
	ks := keystr.NewEncryptedKeystore(c.SecretBytes32)
	pg, err := sql.Open(vars.PostgreSql, dsn)
	if err != nil {
		return err
	}
	defer pg.Close()
	// create and register keys for identities
	log.Infof("initializing %d identities...", len(c.Devices))
	for name, auth := range c.Devices {
		// make sure identity name is a valid UUID
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
		}
		id := ent.Identity{
			Uid:        name,
			PrivateKey: nil,
			PublicKey:  nil,
			Signature:  nil,
			AuthToken:  auth,
		}

		err = decrypt8BitKey()
		if err != nil {
			return err
		}

		err = migrateIdentityToPostgres(id, ks)
		if err != nil {
			return err
		}

		// make sure that all auth tokens from config are being set (this is here for backwards compatibility)
		//if _, ok := i.Protocol.ContextManager.(*FileManager); ok {
		//	err = i.Protocol.SetAuthToken(uid, auth)
		//	if err != nil {
		//		return err
		//	}
		//}
		//
		//err = i.setIdentityAttributes(uid, auth)
		//if err != nil {
		//	return err
		//}
	}

	return nil
}

func transformKeysToPkcs8() error {
	return nil
}

func migrateIdentityToPostgres(identity ent.Identity, ks *keystr.EncryptedKeystore) error {
	db, err := sql.Open(vars.PostgreSql, dm.conn)
	if err != nil {
		return err
	}
	defer db.Close()

	encryptedPrivateKey, err := ks.Encrypt(identity.PrivateKey)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO identity (uid, private_key, public_key, signature, auth_token) VALUES ($1, $2, $3, $4, $5);",
		&identity.Uid, encryptedPrivateKey, &identity.PublicKey, &genesisSignature, &identity.AuthToken)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}
