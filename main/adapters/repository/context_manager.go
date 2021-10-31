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
	StartTransaction(context.Context) (TransactionCtx, error)

	StoreNewIdentity(TransactionCtx, ent.Identity) error

	LoadSignature(TransactionCtx, uuid.UUID) ([]byte, error)
	StoreSignature(TransactionCtx, uuid.UUID, []byte) error

	LoadPrivateKey(uuid.UUID) ([]byte, error)
	LoadPublicKey(uuid.UUID) ([]byte, error)
	LoadAuthToken(uuid.UUID) (string, error)

	IsReady() error
	Close() error
}

type TransactionCtx interface {
	Commit() error
	Rollback() error
}

func GetContextManager(c *config.Config) (ContextManager, error) {
	if c.PostgresDSN != "" {
		return NewSqlDatabaseInfo(c.PostgresDSN, PostgresIdentityTableName, c.DbMaxConns)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set a postgres DSN in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
