package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/postgres"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/sqlite"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

type driverName string

const (
	postgresDriver driverName = "postgres"
	sqliteDriver   driverName = "sqlite"
)

type Database struct {
	driver   driverName
	postgres *postgres.Queries
	sqlite   *sqlite.Queries
}

func NewDatabase(dbConn *sql.DB, driver driverName) (*Database, error) {
	db := &Database{}

	switch driver {
	case postgresDriver:
		db.driver = postgresDriver
		db.postgres = postgres.New(dbConn)
	case sqliteDriver:
		db.driver = sqliteDriver
		db.sqlite = sqlite.New(dbConn)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", db.driver)
	}

	return db, nil
}

func (db *Database) GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.GetExternalIdentityUUIDs(ctx)

	case sqliteDriver:
		// return db.sqlite.GetExternalIdentityUUIDs(ctx)

		uuidStrings, err := db.sqlite.GetExternalIdentityUUIDs(ctx)
		if err != nil {
			return nil, err
		}

		// convert UUIDs from string representation to uuid.UUID type
		// todo: this is a workaround until kyleconroy/sqlc supports overrides for sqlite
		//  related issue: https://github.com/kyleconroy/sqlc/issues/1985
		//  may be fixed by https://github.com/kyleconroy/sqlc/pull/1986
		var uuids []uuid.UUID
		for _, uidString := range uuidStrings {
			uid, err := uuid.Parse(uidString)
			if err != nil {
				return nil, err
			}
			uuids = append(uuids, uid)
		}
		return uuids, nil

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.GetIdentityUUIDs(ctx)

	case sqliteDriver:
		// return db.sqlite.GetIdentityUUIDs(ctx)

		uuidStrings, err := db.sqlite.GetIdentityUUIDs(ctx)
		if err != nil {
			return nil, err
		}

		// convert UUIDs from string representation to uuid.UUID type
		// todo: this is a workaround until kyleconroy/sqlc supports overrides for sqlite
		//  related issue: https://github.com/kyleconroy/sqlc/issues/1985
		//  may be fixed by https://github.com/kyleconroy/sqlc/pull/1986
		var uuids []uuid.UUID
		for _, uidString := range uuidStrings {
			uid, err := uuid.Parse(uidString)
			if err != nil {
				return nil, err
			}
			uuids = append(uuids, uid)
		}
		return uuids, nil

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.LoadActiveFlag(ctx, uid)
	case sqliteDriver:
		active, err := db.sqlite.LoadActiveFlag(ctx, uid.String())
		return sqliteInt64ToBool(active), err
	default:
		return false, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadActiveFlagForUpdate(tx *sql.Tx, uid uuid.UUID) (bool, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid)
	case sqliteDriver:
		active, err := db.sqlite.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid.String())
		return sqliteInt64ToBool(active), err
	default:
		return false, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadAuthForUpdate(tx *sql.Tx, uid uuid.UUID) (string, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).LoadAuthForUpdate(context.Background(), uid)
	case sqliteDriver:
		return db.sqlite.WithTx(tx).LoadAuthForUpdate(context.Background(), uid.String())
	default:
		return "", fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ent.ExternalIdentity, error) {
	switch db.driver {
	case postgresDriver:
		i, err := db.postgres.LoadExternalIdentity(ctx, uid)
		return ent.ExternalIdentity(i), err
	case sqliteDriver:
		i, err := db.sqlite.LoadExternalIdentity(ctx, uid.String())
		if err != nil {
			return ent.ExternalIdentity{}, err
		}
		return ent.ExternalIdentity{
			Uid:       uuid.MustParse(i.Uid), // todo use Parse and handle error
			PublicKey: i.PublicKey,
		}, err
	default:
		return ent.ExternalIdentity{}, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadIdentity(ctx context.Context, uid uuid.UUID) (ent.Identity, error) {
	switch db.driver {
	case postgresDriver:
		i, err := db.postgres.LoadIdentity(context.Background(), uid)
		return ent.Identity(i), err
	case sqliteDriver:
		i, err := db.sqlite.LoadIdentity(context.Background(), uid.String())
		if err != nil {
			return ent.Identity{}, err
		}
		return ent.Identity{
			Uid:        uuid.MustParse(i.Uid), // todo use Parse and handle error
			PrivateKey: i.PrivateKey,
			PublicKey:  i.PublicKey,
			Signature:  i.Signature,
			AuthToken:  i.AuthToken,
			Active:     sqliteInt64ToBool(i.Active),
		}, err
	default:
		return ent.Identity{}, fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) LoadSignatureForUpdate(tx *sql.Tx, uid uuid.UUID) ([]byte, error) {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid)
	case sqliteDriver:
		return db.sqlite.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid.String())
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", db.driver)
	}

}

func (db *Database) StoreActiveFlag(tx *sql.Tx, arg StoreActiveFlagParams) error {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).StoreActiveFlag(context.Background(), postgres.StoreActiveFlagParams(arg))
	case sqliteDriver:
		return db.sqlite.WithTx(tx).StoreActiveFlag(context.Background(), sqlite.StoreActiveFlagParams{
			Uid:    arg.Uid.String(),
			Active: sqliteBoolToInt64(arg.Active),
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) StoreAuth(tx *sql.Tx, arg StoreAuthParams) error {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).StoreAuth(context.Background(), postgres.StoreAuthParams(arg))
	case sqliteDriver:
		return db.sqlite.WithTx(tx).StoreAuth(context.Background(), sqlite.StoreAuthParams{
			Uid:       arg.Uid.String(),
			AuthToken: arg.AuthToken,
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error {
	switch db.driver {
	case postgresDriver:
		return db.postgres.StoreExternalIdentity(ctx, postgres.StoreExternalIdentityParams(arg))
	case sqliteDriver:
		return db.sqlite.StoreExternalIdentity(ctx, sqlite.StoreExternalIdentityParams{
			Uid:       arg.Uid.String(),
			PublicKey: arg.PublicKey,
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) StoreIdentity(tx *sql.Tx, arg StoreIdentityParams) error {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).StoreIdentity(context.Background(), postgres.StoreIdentityParams(arg))
	case sqliteDriver:
		return db.sqlite.WithTx(tx).StoreIdentity(context.Background(), sqlite.StoreIdentityParams{
			Uid:        arg.Uid.String(),
			PrivateKey: arg.PrivateKey,
			PublicKey:  arg.PublicKey,
			Signature:  arg.Signature,
			AuthToken:  arg.AuthToken,
			Active:     sqliteBoolToInt64(arg.Active),
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

func (db *Database) StoreSignature(tx *sql.Tx, arg StoreSignatureParams) error {
	switch db.driver {
	case postgresDriver:
		return db.postgres.WithTx(tx).StoreSignature(context.Background(), postgres.StoreSignatureParams(arg))
	case sqliteDriver:
		return db.sqlite.WithTx(tx).StoreSignature(context.Background(), sqlite.StoreSignatureParams{
			Uid:       arg.Uid.String(),
			Signature: arg.Signature,
		})
	default:
		return fmt.Errorf("unsupported database driver: %s", db.driver)
	}
}

// this is a helper function to convert booleans to integers representing booleans in sqlite
func sqliteBoolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// this is a helper function to convert integers representing booleans in sqlite to booleans
func sqliteInt64ToBool(i int64) bool {
	return i != 0
}
