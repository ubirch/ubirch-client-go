package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	testLoad = 100
)

func TestDatabaseManager(t *testing.T) {
	dm, err := initDB()
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
	require.NotNil(t, tx)

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
	require.NotNil(t, tx)

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

func TestDatabaseManager_StoreActiveFlag(t *testing.T) {
	dm, err := initDB()
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

func TestDatabaseManager_SetSignature(t *testing.T) {
	dm, err := initDB()
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

func TestDatabaseManager_LoadSignatureForUpdate(t *testing.T) {
	dm, err := initDB()
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

	// get lock on signature
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	_, err = dm.LoadSignatureForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)

	// try to get lock on signature again and wait a second for the lock before context gets canceled
	ctxWithTimeout, cancelWithTimeout := context.WithTimeout(context.Background(), time.Second)
	defer cancelWithTimeout()

	tx2, err := dm.StartTransaction(ctxWithTimeout)
	require.NoError(t, err)

	_, err = dm.LoadSignatureForUpdate(tx2, testIdentity.Uid)
	assert.EqualError(t, err, "pq: canceling statement due to user request")
}

func TestDatabaseManager_StoreAuth(t *testing.T) {
	dm, err := initDB()
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

func TestNewSqlDatabaseInfo_Ready(t *testing.T) {
	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	err = dm.IsReady()
	require.NoError(t, err)
}

func TestNewSqlDatabaseInfo_NotReady(t *testing.T) {
	// use DSN that is valid, but not reachable
	unreachableDSN := "postgres://nousr:nopwd@localhost:0000/nodatabase"

	// we expect no error here
	dm, err := NewSqlDatabaseInfo(PostgreSQL, unreachableDSN, 0)
	require.NoError(t, err)
	defer func(dm *DatabaseManager) {
		err := dm.Close()
		if err != nil {
			t.Error(err)
		}
	}(dm)

	err = dm.IsReady()
	require.Error(t, err)
}

func TestStoreExisting(t *testing.T) {
	dm, err := initDB()
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

func TestDatabaseManager_CancelTransaction(t *testing.T) {
	dm, err := initDB()
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

	// check transaction was rolled back
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	// make sure identity can be stored now
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)
}

func TestDatabaseManager_StartTransaction(t *testing.T) {
	c, err := getConfig()
	require.NoError(t, err)

	dm, err := NewSqlDatabaseInfo(PostgreSQL, c.PostgresDSN, 1)
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

func TestDatabaseManager_InvalidTransactionCtx(t *testing.T) {
	dm, err := initDB()
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

func TestDatabaseLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
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

func TestDatabaseManager_RecoverUndefinedTable(t *testing.T) {
	c, err := getConfig()
	require.NoError(t, err)

	pg, err := sql.Open(PostgreSQL, c.PostgresDSN)
	require.NoError(t, err)

	dm := &DatabaseManager{
		options:    &sql.TxOptions{},
		db:         pg,
		driverName: PostgreSQL,
	}

	_, err = dm.LoadIdentity(uuid.New())
	assert.Equal(t, ErrNotExist, err)
}

func TestDatabaseManager_Retry(t *testing.T) {
	c, err := getConfig()
	require.NoError(t, err)

	dm, err := NewSqlDatabaseInfo(PostgreSQL, c.PostgresDSN, 101)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < 101; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := dm.StartTransaction(ctx)
			if err != nil {
				if pqErr, ok := err.(*pq.Error); ok {
					switch pqErr.Code {
					case "55P03", "53300", "53400":
						return
					}
				}
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func getConfig() (*config.Config, error) {
	configFileName := "config_test.json"
	fileHandle, err := os.Open(filepath.Join("../../", configFileName))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v \n"+
			"--------------------------------------------------------------------------------\n"+
			"Please provide a configuration file \"%s\" in the main directory which contains\n"+
			"a DSN for a postgres database in order to test the database context management.\n\n"+
			"!!! THIS MUST BE DIFFERENT FROM THE DSN USED FOR THE ACTUAL CONTEXT !!!\n\n"+
			"{\n\t\"postgresDSN\": \"postgres://<username>:<password>@<hostname>:5432/<TEST-database>\"\n}\n"+
			"--------------------------------------------------------------------------------",
			err, configFileName)
	}
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()

	c := &config.Config{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func initDB() (*DatabaseManager, error) {
	c, err := getConfig()
	if err != nil {
		return nil, err
	}

	dm, err := NewSqlDatabaseInfo(PostgreSQL, c.PostgresDSN, c.DbMaxConns)
	if err != nil {
		return nil, err
	}

	return dm, nil
}

func cleanUpDB(t *testing.T, dm *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", IdentityTableName)
	err := dm.retry(func() error {
		_, err := dm.db.Exec(dropTableQuery)
		return err
	})
	assert.NoError(t, err)

	err = dm.Close()
	assert.NoError(t, err)
}

func generateRandomIdentity() ent.Identity {
	uid := uuid.New()

	keystore := &MockKeystorer{}

	c := ubirch.ECDSACryptoContext{Keystore: keystore}

	err := c.GenerateKey(uid)
	if err != nil {
		panic(err)
	}

	priv, err := keystore.GetPrivateKey(uid)
	if err != nil {
		panic(err)
	}

	pub, err := keystore.GetPublicKey(uid)
	if err != nil {
		panic(err)
	}

	sig := make([]byte, 64)
	rand.Read(sig)

	auth := make([]byte, 16)
	rand.Read(auth)

	return ent.Identity{
		Uid:        uuid.New(),
		PrivateKey: priv,
		PublicKey:  pub,
		Signature:  sig,
		AuthToken:  base64.StdEncoding.EncodeToString(auth),
	}
}

func storeIdentity(ctxManager ContextManager, id ent.Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("StartTransaction: %v", err)
	}

	err = ctxManager.StoreIdentity(tx, id)
	if err != nil {
		return fmt.Errorf("StoreIdentity: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Commit: %v", err)
	}

	return nil
}

func dbCheckAuth(auth, authToCheck string) error {
	if auth != authToCheck {
		return fmt.Errorf("auth check failed")
	}

	return nil
}

func checkIdentity(ctxManager ContextManager, id ent.Identity, checkAuth func(string, string) error, wg *sync.WaitGroup) error {
	defer wg.Done()

	fetchedId, err := ctxManager.LoadIdentity(id.Uid)
	if err != nil {
		return fmt.Errorf("LoadIdentity: %v", err)
	}

	if !bytes.Equal(fetchedId.PrivateKey, id.PrivateKey) {
		return fmt.Errorf("unexpected private key")
	}

	if !bytes.Equal(fetchedId.PublicKey, id.PublicKey) {
		return fmt.Errorf("unexpected public key")
	}

	err = checkAuth(fetchedId.AuthToken, id.AuthToken)
	if err != nil {
		return fmt.Errorf("checkAuth: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("StartTransaction: %v", err)
	}

	sig, err := ctxManager.LoadSignatureForUpdate(tx, id.Uid)
	if err != nil {
		return fmt.Errorf("LoadSignatureForUpdate: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Commit: %v", err)
	}

	if !bytes.Equal(sig, id.Signature) {
		return fmt.Errorf("LoadSignatureForUpdate returned unexpected value")
	}

	return nil
}
