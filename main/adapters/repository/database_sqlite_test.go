package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

func TestDatabaseManager_sqlite(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = dm.LoadActiveFlag(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)

	_, err = dm.LoadActiveFlagForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = dm.LoadSignatureForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	err = tx.Rollback()
	require.NoError(t, err)

	// store identity
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	active, err := dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, active)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	active, err = dm.LoadActiveFlagForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, active)

	sig, err := dm.LoadSignatureForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Signature, sig)

	auth, err := dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.AuthToken, auth)

	err = tx.Commit()
	require.NoError(t, err)

	i, err := dm.LoadIdentity(testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.PrivateKey, i.PrivateKey)
	assert.Equal(t, testIdentity.PublicKey, i.PublicKey)
	assert.Equal(t, testIdentity.AuthToken, i.AuthToken)
}

func TestDatabaseManager_sqlite_StoreActiveFlag(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	active, err := dm.LoadActiveFlagForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, active)

	err = dm.StoreActiveFlag(tx, testIdentity.Uid, !active)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	active, err = dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, active)
}

func TestDatabaseManager_sqlite_SetSignature(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	newSignature := make([]byte, 64)
	rand.Read(newSignature)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	sig, err := dm.LoadSignatureForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Signature, sig)

	err = dm.StoreSignature(tx, testIdentity.Uid, newSignature)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	sig, err = dm.LoadSignatureForUpdate(tx2, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, newSignature, sig)
}

func TestDatabaseManager_sqlite_LoadSignatureForUpdate(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// get lock on signature
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)

	// try to get lock on signature again and wait a second for the lock before context gets canceled
	ctxWithTimeout, cancelWithTimeout := context.WithTimeout(context.Background(), time.Second)
	defer cancelWithTimeout()

	_, err = dm.StartTransaction(ctxWithTimeout)
	assert.EqualError(t, err, "context deadline exceeded")
}

func TestDatabaseManager_sqlite_StoreAuth(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	newAuth := make([]byte, 64)
	rand.Read(newAuth)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	auth, err := dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.AuthToken, auth)

	err = dm.StoreAuth(tx, testIdentity.Uid, base64.StdEncoding.EncodeToString(newAuth))
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	auth, err = dm.LoadAuthForUpdate(tx2, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(newAuth), auth)
}

func TestNewSqlDatabaseInfo_Ready_sqlite(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	err = dm.IsReady()
	require.NoError(t, err)
}

func TestStoreExisting_sqlite(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// store identity
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// store same identity again
	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	err = dm.StoreIdentity(tx2, testIdentity)
	assert.Error(t, err)
}

func TestDatabaseManager_sqlite_CancelTransaction(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := generateRandomIdentity()

	// store identity, but cancel context, so transaction will be rolled back
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	cancel()

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)
}

func TestDatabaseManager_sqlite_StartTransaction(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")

	dm, err := NewSqlDatabaseInfo(SQLite, dsn, 1)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	assert.NotNil(t, tx)

	tx2, err := dm.StartTransaction(ctx)
	assert.EqualError(t, err, "context deadline exceeded")
	assert.Nil(t, tx2)
}

func TestDatabaseManager_sqlite_InvalidTransactionCtx(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	i := ent.Identity{}
	mockCtx := &mockTx{}

	err = dm.StoreIdentity(mockCtx, i)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	err = dm.StoreActiveFlag(mockCtx, i.Uid, false)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	_, err = dm.LoadActiveFlagForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	err = dm.StoreSignature(mockCtx, i.Uid, nil)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	_, err = dm.LoadSignatureForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	err = dm.StoreAuth(mockCtx, i.Uid, "")
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")

	_, err = dm.LoadAuthForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *sql.Tx")
}

func TestDatabaseLoad_sqlite(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// generate identities
	var testIdentities []ent.Identity
	for i := 0; i < testLoad; i++ {
		testIdentities = append(testIdentities, generateRandomIdentity())
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, id ent.Identity) {
			err := storeIdentity(dm, id, wg)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", id.Uid, err)
			}
		}(i, testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			err := checkIdentity(dm, id, dbCheckAuth, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()

	// FIXME
	//if dm.db.Stats().OpenConnections > dm.db.Stats().Idle {
	//	t.Errorf("%d open connections, %d idle", dm.db.Stats().OpenConnections, dm.db.Stats().Idle)
	//}
}

func TestDatabaseManager_sqlite_RecoverUndefinedTable(t *testing.T) {
	db, err := sql.Open(SQLite, filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)

	dm := &DatabaseManager{
		options:    &sql.TxOptions{},
		db:         db,
		driverName: SQLite,
	}

	_, err = dm.LoadIdentity(uuid.New())
	assert.Equal(t, ErrNotExist, err)
}

func TestDatabaseManager_sqlite_Retry(t *testing.T) {
	dm, err := initSQLiteDB(t)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := dm.StartTransaction(ctx)
			if err != nil {
				if liteErr, ok := err.(sqlite3.Error); ok {
					switch liteErr.Code {
					case sqlite3.ErrBusy, sqlite3.ErrLocked:
						return
					}
				}
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func initSQLiteDB(t *testing.T) (*DatabaseManager, error) {
	dsn := filepath.Join(t.TempDir(), "test.db?_journal_mode=WAL&_txlock=exclusive")

	return NewSqlDatabaseInfo(SQLite, dsn, 0)
}
