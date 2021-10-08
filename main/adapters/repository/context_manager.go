package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

var (
	ErrNotExist = errors.New("entry does not exist")
)

type ContextManager interface {
	StartTransaction(ctx context.Context) (transactionCtx interface{}, err error)
	CommitTransaction(transactionCtx interface{}) error

	StoreNewIdentity(transactionCtx interface{}, id *ent.Identity) error
	GetIdentityWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, id *ent.Identity, err error)

	SetSignature(transactionCtx interface{}, uid uuid.UUID, signature []byte) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	GetPublicKey(uid uuid.UUID) ([]byte, error)
	GetAuthToken(uid uuid.UUID) (string, error)
}

func GetCtxManager(c config.Config) (ContextManager, error) {
	if c.PostgresDSN != "" {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set a postgres DSN in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
