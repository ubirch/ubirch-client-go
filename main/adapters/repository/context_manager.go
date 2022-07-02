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

	StoreIdentity(TransactionCtx, ent.Identity) error
	LoadIdentity(uuid.UUID) (*ent.Identity, error)

	StoreActiveFlag(TransactionCtx, uuid.UUID, bool) error
	LoadActiveFlagForUpdate(TransactionCtx, uuid.UUID) (bool, error)
	LoadActiveFlag(uuid.UUID) (bool, error)

	StoreSignature(TransactionCtx, uuid.UUID, []byte) error
	LoadSignatureForUpdate(TransactionCtx, uuid.UUID) ([]byte, error)

	StoreAuth(TransactionCtx, uuid.UUID, string) error
	LoadAuthForUpdate(TransactionCtx, uuid.UUID) (string, error)

	IsReady() error
	Close() error
}

type TransactionCtx interface {
	Commit() error
	Rollback() error
}

func GetContextManager(c *config.Config) (ContextManager, error) {
	if c.PostgresDSN != "" {
		return NewSqlDatabaseInfo(PostgreSQL, c.PostgresDSN, c.DbMaxConns)
	} else if c.SqliteDSN != "" {
		return NewSqlDatabaseInfo(SQLite, c.SqliteDSN, c.DbMaxConns)
	} else {
		return nil, fmt.Errorf("file-based context management is not supported in the current version. " +
			"Please set a DSN for a postgreSQL or SQLite database in the configuration and conntect to a database or downgrade to a version < 2.0.0")
	}
}
