package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

const (
	commit   = true
	rollback = false
)

var (
	ErrExists = errors.New("entry already exists")
)

type ContextManager interface {
	StartTransaction(ctx context.Context) (transactionCtx interface{}, err error)
	StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error)
	CloseTransaction(transactionCtx interface{}, commit bool) error

	Exists(uid uuid.UUID) (bool, error)

	StoreNewIdentity(transactionCtx interface{}, identity *ent.Identity) error
	FetchIdentity(transactionCtx interface{}, uid uuid.UUID) (*ent.Identity, error)

	SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	GetPublicKey(uid uuid.UUID) ([]byte, error)
	GetAuthToken(uid uuid.UUID) (string, error)
}

func GetCtxManager(c config.Config) (ContextManager, error) {
	if c.DsnInitContainer {
		return NewSqlDatabaseInfo(c)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set DSN parameters in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
