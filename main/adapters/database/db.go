package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/postgres"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/sqlite"
)

type Querier interface {
	GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error)
	GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error)
	LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error)
	LoadActiveFlagForUpdate(ctx context.Context, uid uuid.UUID) (bool, error)
	LoadAuthForUpdate(ctx context.Context, uid uuid.UUID) (string, error)
	LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ExternalIdentity, error)
	LoadIdentity(ctx context.Context, uid uuid.UUID) (Identity, error)
	LoadSignatureForUpdate(ctx context.Context, uid uuid.UUID) ([]byte, error)
	StoreActiveFlag(ctx context.Context, arg StoreActiveFlagParams) error
	StoreAuth(ctx context.Context, arg StoreAuthParams) error
	StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error
	StoreIdentity(ctx context.Context, arg StoreIdentityParams) error
	StoreSignature(ctx context.Context, arg StoreSignatureParams) error
}

type ExternalIdentity struct {
	Uid       uuid.UUID
	PublicKey []byte
}

type Identity struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
	Active     bool
}

type StoreActiveFlagParams struct {
	Active bool
	Uid    uuid.UUID
}

type StoreAuthParams struct {
	AuthToken string
	Uid       uuid.UUID
}

type StoreExternalIdentityParams struct {
	Uid       uuid.UUID
	PublicKey []byte
}

type StoreIdentityParams struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
	Active     bool
}

type StoreSignatureParams struct {
	Signature []byte
	Uid       uuid.UUID
}

type driver string

const (
	PostgresDriver driver = "pgx"
	SqliteDriver   driver = "sqlite"
)

type Database struct {
	driver   driver
	postgres *postgres.Queries
	sqlite   *sqlite.Queries
}

func NewDatabase(dbConn *sql.DB) *Database {
	db := &Database{
		driver: PostgresDriver,
	}

	switch db.driver {
	case PostgresDriver:
		db.postgres = postgres.New(dbConn)

	case SqliteDriver:
		db.sqlite = sqlite.New(dbConn)

	default:
		panic("panic, srsly ⊂(⊙д⊙)つ")
	}

	return db
}

// Database needs to implement Querier.
var _ Querier = &Database{}

func (db *Database) GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	switch db.driver {
	case PostgresDriver:
		return db.postgres.GetExternalIdentityUUIDs(ctx)

	case SqliteDriver:
		// return db.sqlite.GetExternalIdentityUUIDs(ctx)
		// todo: this is a workaround until kyleconroy/sqlc supports overrides for sqlite
		uuidStrings, err := db.sqlite.GetExternalIdentityUUIDs(ctx)
		if err != nil {
			return nil, err
		}
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
		panic("panic, srsly ⊂(⊙д⊙)つ")

	}
}

func (db *Database) GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadActiveFlagForUpdate(ctx context.Context, uid uuid.UUID) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadAuthForUpdate(ctx context.Context, uid uuid.UUID) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ExternalIdentity, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadIdentity(ctx context.Context, uid uuid.UUID) (Identity, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) LoadSignatureForUpdate(ctx context.Context, uid uuid.UUID) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (db *Database) StoreActiveFlag(ctx context.Context, arg StoreActiveFlagParams) error {
	//TODO implement me
	panic("implement me")
}

func (db *Database) StoreAuth(ctx context.Context, arg StoreAuthParams) error {
	//TODO implement me
	panic("implement me")
}

func (db *Database) StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error {
	//TODO implement me
	panic("implement me")
}

func (db *Database) StoreIdentity(ctx context.Context, arg StoreIdentityParams) error {
	//TODO implement me
	panic("implement me")
}

func (db *Database) StoreSignature(ctx context.Context, arg StoreSignatureParams) error {
	//TODO implement me
	panic("implement me")
}
