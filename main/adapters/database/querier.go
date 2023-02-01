package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

type Querier interface {
	GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error)
	GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error)
	LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error)
	LoadActiveFlagForUpdate(tx *sql.Tx, uid uuid.UUID) (bool, error)
	LoadAuthForUpdate(tx *sql.Tx, uid uuid.UUID) (string, error)
	LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ent.ExternalIdentity, error)
	LoadIdentity(ctx context.Context, uid uuid.UUID) (ent.Identity, error)
	LoadSignatureForUpdate(tx *sql.Tx, uid uuid.UUID) ([]byte, error)
	StoreActiveFlag(tx *sql.Tx, arg StoreActiveFlagParams) error
	StoreAuth(tx *sql.Tx, arg StoreAuthParams) error
	StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error
	StoreIdentity(tx *sql.Tx, arg StoreIdentityParams) error
	StoreSignature(tx *sql.Tx, arg StoreSignatureParams) error
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
