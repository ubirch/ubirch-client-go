package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/ubirch/ubirch-client-go/main/adapters/database/postgres"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

type PostgresDatabase struct {
	postgres *postgres.Queries
}

// PostgresDatabase needs to implement Querier.
var _ Querier = &PostgresDatabase{}

func NewPostgresDatabase(dbConn *sql.DB) *PostgresDatabase {
	return &PostgresDatabase{postgres: postgres.New(dbConn)}
}

func (db *PostgresDatabase) GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	return db.postgres.GetExternalIdentityUUIDs(ctx)
}

func (db *PostgresDatabase) GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	return db.postgres.GetIdentityUUIDs(ctx)
}

func (db *PostgresDatabase) LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error) {
	return db.postgres.LoadActiveFlag(ctx, uid)
}

func (db *PostgresDatabase) LoadActiveFlagForUpdate(tx *sql.Tx, uid uuid.UUID) (bool, error) {
	return db.postgres.WithTx(tx).LoadActiveFlagForUpdate(context.Background(), uid)
}

func (db *PostgresDatabase) LoadAuthForUpdate(tx *sql.Tx, uid uuid.UUID) (string, error) {
	return db.postgres.WithTx(tx).LoadAuthForUpdate(context.Background(), uid)
}

func (db *PostgresDatabase) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ent.ExternalIdentity, error) {
	i, err := db.postgres.LoadExternalIdentity(ctx, uid)
	return ent.ExternalIdentity(i), err
}

func (db *PostgresDatabase) LoadIdentity(ctx context.Context, uid uuid.UUID) (ent.Identity, error) {
	i, err := db.postgres.LoadIdentity(ctx, uid)
	return ent.Identity(i), err
}

func (db *PostgresDatabase) LoadSignatureForUpdate(tx *sql.Tx, uid uuid.UUID) ([]byte, error) {
	return db.postgres.WithTx(tx).LoadSignatureForUpdate(context.Background(), uid)
}

func (db *PostgresDatabase) StoreActiveFlag(tx *sql.Tx, arg StoreActiveFlagParams) error {
	return db.postgres.WithTx(tx).StoreActiveFlag(context.Background(), postgres.StoreActiveFlagParams(arg))
}

func (db *PostgresDatabase) StoreAuth(tx *sql.Tx, arg StoreAuthParams) error {
	return db.postgres.WithTx(tx).StoreAuth(context.Background(), postgres.StoreAuthParams(arg))
}

func (db *PostgresDatabase) StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error {
	return db.postgres.StoreExternalIdentity(ctx, postgres.StoreExternalIdentityParams(arg))
}

func (db *PostgresDatabase) StoreIdentity(tx *sql.Tx, arg StoreIdentityParams) error {
	return db.postgres.WithTx(tx).StoreIdentity(context.Background(), postgres.StoreIdentityParams(arg))
}

func (db *PostgresDatabase) StoreSignature(tx *sql.Tx, arg StoreSignatureParams) error {
	return db.postgres.WithTx(tx).StoreSignature(context.Background(), postgres.StoreSignatureParams(arg))
}

func (db *PostgresDatabase) isRecoverable(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Code == "55P03" || // lock_not_available
			pqErr.Code == "53300" || // too_many_connections
			pqErr.Code == "53400" { // configuration_limit_exceeded
			time.Sleep(10 * time.Millisecond)
			return true
		}
		log.Errorf("unexpected postgres database error: %v", pqErr)
	}
	return false
}
