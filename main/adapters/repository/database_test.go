package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	testTableName = "test_identity"
	testLoad      = 100
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

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)

	_, err = dm.LoadSignature(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	err = tx.Commit()
	require.NoError(t, err)

	// store identity
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	sig, err := dm.LoadSignature(tx, testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.Signature, sig)

	i, err := dm.LoadIdentity(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.PrivateKey, i.PrivateKey)
	assert.Equal(t, testIdentity.PublicKey, i.PublicKey)
	assert.Equal(t, testIdentity.AuthToken, i.AuthToken)
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

	err = dm.StoreSignature(tx, testIdentity.Uid, newSignature)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	sig, err := dm.LoadSignature(tx2, testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, newSignature, sig)
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
	dm, err := NewSqlDatabaseInfo(unreachableDSN, testTableName, 0)
	if err != nil {
		t.Fatal(err)
	}
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

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)
}

func TestDatabaseLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
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

func TestDatabaseManager_Retry(t *testing.T) {
	c, err := getDatabaseConfig()
	require.NoError(t, err)

	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, testTableName, 101)
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

type dbConfig struct {
	PostgresDSN string
	DbMaxConns  int
}

func getDatabaseConfig() (*dbConfig, error) {
	configFileName := "../../config.json"
	fileHandle, err := os.Open(configFileName)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v \n"+
			"--------------------------------------------------------------------------------\n"+
			"Please provide a configuration file \"%s\" which contains a DSN for\n"+
			"a postgres database in order to test the database connection.\n"+
			"{\n\t\"postgresDSN\": \"postgres://<username>:<password>@<hostname>:5432/<database>\"\n}\n"+
			"--------------------------------------------------------------------------------",
			err, configFileName)
	}
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func initDB() (*DatabaseManager, error) {
	c, err := getDatabaseConfig()
	if err != nil {
		return nil, err
	}

	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, testTableName, c.DbMaxConns)
	if err != nil {
		return nil, err
	}

	return dm, nil
}

func cleanUpDB(t *testing.T, dm *DatabaseManager) {
	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", testTableName)
	_, err := dm.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}

	err = dm.Close()
	if err != nil {
		t.Error(err)
	}
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

	sig, err := ctxManager.LoadSignature(tx, id.Uid)
	if err != nil {
		return fmt.Errorf("LoadSignature: %v", err)
	}

	if !bytes.Equal(sig, id.Signature) {
		return fmt.Errorf("LoadSignature returned unexpected value")
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Commit: %v", err)
	}

	return nil
}
