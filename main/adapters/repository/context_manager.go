package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

var (
	ErrNotExist = errors.New("entry does not exist")
)

type ContextManager interface {
	StartTransaction(context.Context) (TransactionCtx, error)

	StoreIdentity(TransactionCtx, ent.Identity) error
	LoadIdentity(uuid.UUID) (*ent.Identity, error)

	StoreActiveFlag(TransactionCtx, uuid.UUID, bool) error
	LoadActiveFlagForUpdate(TransactionCtx, uuid.UUID) (bool, error)
	LoadActiveFlag(uuid.UUID) (bool, error)

	StoreSignature(TransactionCtx, uuid.UUID, []byte) error
	LoadSignatureForUpdate(TransactionCtx, uuid.UUID) ([]byte, error)

	StoreAuth(TransactionCtx, uuid.UUID, string) error
	LoadAuthForUpdate(TransactionCtx, uuid.UUID) (string, error)

	StoreExternalIdentity(context.Context, ent.ExternalIdentity) error
	LoadExternalIdentity(context.Context, uuid.UUID) (*ent.ExternalIdentity, error)

	GetIdentityUUIDs() ([]uuid.UUID, error)
	GetExternalIdentityUUIDs() ([]uuid.UUID, error)

	IsReady() error
	Close() error
}

type TransactionCtx interface {
	Commit() error
	Rollback() error
}
