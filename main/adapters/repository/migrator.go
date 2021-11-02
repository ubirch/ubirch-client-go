package repository

import (
	"context"
	"database/sql"
	"fmt"
)

<<<<<<<< HEAD:main/adapters/repository/migrator.go
func Migrate(c *config.Config, configDir string) error {
	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, c.DbMaxConns)
	if err != nil {
		return err
	}

	for i := 0; i < 10; i++ {
		err = dm.IsReady()
		if err != nil {
			log.Warn(err)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		return err
	}

	txCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	migration := &Migration{
		id: MigrationID,
	}

	err = migration.getVersion(txCtx, dm)
	if err != nil {
		return err
	}

	if migration.version == MigrationVersionLatest {
		log.Infof("database migration version already up to date")
		return nil
	}
	log.Debugf("database migration version: %s / application migration version: %s", migration.version, MigrationVersionLatest)

	p, err := NewExtendedProtocol(dm, c)
	if err != nil {
		return err
	}

	if migration.version == MigrationVersionNoDB {
		err = migrateIdentities(c, configDir, p)
		if err != nil {
			return fmt.Errorf("could not migrate file-based context to database: %v", err)
		}

		log.Infof("successfully migrated file-based context to database")
	}

	if migration.version == MigrationVersionInit {
		err = hashAuthTokens(dm, p)
		if err != nil {
			return fmt.Errorf("could not hash auth tokens in database: %v", err)
		}

		log.Infof("successfully hashed auth tokens in database")
		migration.version = MigrationVersionHashedAuth
	}

	if migration.version == MigrationVersionHashedAuth {
		err = addColumnActiveBoolean(dm)
		if err != nil {
			return fmt.Errorf("could not add column \"active\" to database table: %v", err)
		}

		log.Infof("successfully added column \"active\" to database table")
	}

	migration.version = MigrationVersionLatest
	return migration.updateVersion()
}

func getIdentitiesFromLegacyCtx(c *config.Config, configDir string) ([]ent.Identity, error) {
	log.Infof("getting existing identities from file system")

	secret16Bytes, err := base64.StdEncoding.DecodeString(c.Secret16Base64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 encoded secret for legacy key store decoding (%s): %v", c.Secret16Base64, err)
	}
	if len(secret16Bytes) != 16 {
		return nil, fmt.Errorf("invalid secret for legacy key store decoding: secret length must be 16 bytes (is %d)", len(secret16Bytes))
	}

	fileManager, err := NewFileManager(configDir, secret16Bytes)
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

func migrateIdentities(c *config.Config, configDir string, p *ExtendedProtocol) error {
	// migrate from file based context
	identitiesToPort, err := getIdentitiesFromLegacyCtx(c, configDir)
	if err != nil {
		return err
	}

	log.Infof("starting migration from files to DB...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for i, id := range identitiesToPort {
		log.Infof("%4d: %s", i+1, id.Uid)

		initialized, err := p.IsInitialized(id.Uid)
		if err != nil {
			return err
		}

		if initialized {
			log.Warnf("skipping %s: already initialized", id.Uid)
			continue
		}

		err = p.StoreIdentity(tx, id)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func hashAuthTokens(dm *DatabaseManager, p *ExtendedProtocol) error {
	query := fmt.Sprintf("SELECT uid, auth_token FROM %s FOR UPDATE", PostgresIdentityTableName)

	rows, err := dm.db.Query(query)
	if err != nil {
		return err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Error(err)
		}
	}(rows)

	var (
		uid  uuid.UUID
		auth string
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for rows.Next() {
		err = rows.Scan(&uid, &auth)
		if err != nil {
			return err
		}

		// make sure that the password is not already hashed before hashing
		isHashed, err := isArgon2idPasswordHash(auth)
		if err != nil {
			return err
		}

		if isHashed {
			continue
		}

		pwHash, err := p.pwHasher.GeneratePasswordHash(ctx, auth, p.pwHasherParams)
		if err != nil {
			return err
		}

		err = storeAuth(dm, uid, pwHash)
		if err != nil {
			return err
		}
	}

	return rows.Err()
}

func isArgon2idPasswordHash(pw string) (bool, error) {
	vals := strings.Split(pw, "$")
	if len(vals) != 6 {
		return false, nil
	}

	var (
		v    int
		m, t uint32
		p    uint8
	)

	_, err := fmt.Sscanf(vals[2], "v=%d", &v)
	if err != nil {
		return false, err
	}

	if v != argon2.Version {
		return false, fmt.Errorf("unsupported argon2id version: %d", v)
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &m, &t, &p)
	if err != nil {
		return false, err
	}

	_, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return false, err
	}

	_, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return false, err
	}

	return true, nil
}

func storeAuth(dm *DatabaseManager, uid uuid.UUID, auth string) error {
	query := fmt.Sprintf("UPDATE %s SET auth_token = $1 WHERE uid = $2;", PostgresIdentityTableName)

	_, err := dm.db.Exec(query, &auth, uid)

	return err
}

func addColumnActiveBoolean(dm *DatabaseManager) error {
	query := fmt.Sprintf(
		"ALTER TABLE %s ADD active boolean NOT NULL DEFAULT(TRUE)", PostgresIdentityTableName)
========
const (
	PostgresIdentity = iota
	PostgresVersion
	PostgresIdentityTableName = "identity"
	PostgresVersionTableName  = "version"
	MigrationID               = "dbMigration"
	MigrationVersion          = "2.0"
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

func (dm *DatabaseManager) CreateTable(tableType int, tableName string) error {
	query := fmt.Sprintf(create[tableType], tableName)
	_, err := dm.db.Exec(query)
	return err
}

func getVersion(ctx context.Context, dm *DatabaseManager, migration *Migration) (*sql.Tx, error) {
	err := dm.CreateTable(PostgresVersion, PostgresVersionTableName)
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
>>>>>>>> minor refactoring, enhanced CreateTable method, moved migration into separate file:main/adapters/repository/database_init.go

	_, err := dm.db.Exec(query)

	return err
}
