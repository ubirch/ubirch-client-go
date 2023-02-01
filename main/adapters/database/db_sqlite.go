package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/sqlite"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
	sqliteLib "modernc.org/sqlite"
)

type SqliteDatabase struct {
	sqlite *sqlite.Queries
}

// SqliteDatabase needs to implement Querier.
var _ Querier = &SqliteDatabase{}

func NewSqliteDatabase(dbConn *sql.DB) *SqliteDatabase {
	return &SqliteDatabase{sqlite: sqlite.New(dbConn)}
}

func (db *SqliteDatabase) GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
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
}

func (db *SqliteDatabase) GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
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
}

func (db *SqliteDatabase) LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error) {
	active, err := db.sqlite.LoadActiveFlag(ctx, uid.String())
	return int64ToBool(active), err
}

func (db *SqliteDatabase) LoadActiveFlagForUpdate(tx *sql.Tx, uid uuid.UUID) (bool, error) {
	active, err := db.sqlite.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid.String())
	return int64ToBool(active), err
}

func (db *SqliteDatabase) LoadAuthForUpdate(tx *sql.Tx, uid uuid.UUID) (string, error) {
	return db.sqlite.WithTx(tx).LoadAuthForUpdate(context.Background(), uid.String())
}

func (db *SqliteDatabase) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ent.ExternalIdentity, error) {
	i, err := db.sqlite.LoadExternalIdentity(ctx, uid.String())
	if err != nil {
		return ent.ExternalIdentity{}, err
	}
	return ent.ExternalIdentity{
		Uid:       uuid.MustParse(i.Uid), // todo use Parse and handle error
		PublicKey: i.PublicKey,
	}, err
}

func (db *SqliteDatabase) LoadIdentity(ctx context.Context, uid uuid.UUID) (ent.Identity, error) {
	i, err := db.sqlite.LoadIdentity(ctx, uid.String())
	if err != nil {
		return ent.Identity{}, err
	}
	return ent.Identity{
		Uid:        uuid.MustParse(i.Uid), // todo use Parse and handle error
		PrivateKey: i.PrivateKey,
		PublicKey:  i.PublicKey,
		Signature:  i.Signature,
		AuthToken:  i.AuthToken,
		Active:     int64ToBool(i.Active),
	}, err
}

func (db *SqliteDatabase) LoadSignatureForUpdate(tx *sql.Tx, uid uuid.UUID) ([]byte, error) {
	return db.sqlite.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid.String())
}

func (db *SqliteDatabase) StoreActiveFlag(tx *sql.Tx, arg StoreActiveFlagParams) error {
	return db.sqlite.WithTx(tx).StoreActiveFlag(context.Background(), sqlite.StoreActiveFlagParams{
		Uid:    arg.Uid.String(),
		Active: boolToInt64(arg.Active),
	})
}

func (db *SqliteDatabase) StoreAuth(tx *sql.Tx, arg StoreAuthParams) error {
	return db.sqlite.WithTx(tx).StoreAuth(context.Background(), sqlite.StoreAuthParams{
		Uid:       arg.Uid.String(),
		AuthToken: arg.AuthToken,
	})
}

func (db *SqliteDatabase) StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error {
	return db.sqlite.StoreExternalIdentity(ctx, sqlite.StoreExternalIdentityParams{
		Uid:       arg.Uid.String(),
		PublicKey: arg.PublicKey,
	})
}

func (db *SqliteDatabase) StoreIdentity(tx *sql.Tx, arg StoreIdentityParams) error {
	return db.sqlite.WithTx(tx).StoreIdentity(context.Background(), sqlite.StoreIdentityParams{
		Uid:        arg.Uid.String(),
		PrivateKey: arg.PrivateKey,
		PublicKey:  arg.PublicKey,
		Signature:  arg.Signature,
		AuthToken:  arg.AuthToken,
		Active:     boolToInt64(arg.Active),
	})
}

func (db *SqliteDatabase) StoreSignature(tx *sql.Tx, arg StoreSignatureParams) error {
	return db.sqlite.WithTx(tx).StoreSignature(context.Background(), sqlite.StoreSignatureParams{
		Uid:       arg.Uid.String(),
		Signature: arg.Signature,
	})
}

func (db *SqliteDatabase) isRecoverable(err error) bool {
	if liteErr, ok := err.(*sqliteLib.Error); ok {
		if liteErr.Code() == 5 || // SQLITE_BUSY
			liteErr.Code() == 6 || // SQLITE_LOCKED
			liteErr.Code() == 261 { // SQLITE_BUSY_RECOVERY
			time.Sleep(10 * time.Millisecond)
			return true
		}
		log.Errorf("unexpected sqlite database error: %v", liteErr)
	}
	return false
}

// this is a helper function to convert booleans to integers representing booleans in sqlite
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// this is a helper function to convert integers representing booleans in sqlite to booleans
func int64ToBool(i int64) bool {
	return i != 0
}
