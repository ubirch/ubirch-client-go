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

type StorageManager interface {
	StartTransaction(context.Context) (TransactionCtx, error)

	StoreNewIdentity(TransactionCtx, *ent.Identity) error
	GetIdentityWithLock(context.Context, uuid.UUID) (TransactionCtx, *ent.Identity, error)

	SetSignature(TransactionCtx, uuid.UUID, []byte) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	GetPublicKey(uid uuid.UUID) ([]byte, error)
	GetAuthToken(uid uuid.UUID) (string, error)
}

type TransactionCtx interface {
	Commit() error
}

func GetStorageManager(c config.Config) (StorageManager, error) {
	if c.PostgresDSN != "" {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgreSqlIdentityTableName)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set a postgres DSN in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
