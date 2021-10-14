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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/ent"
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
	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	_, err = dm.GetSignature(tx, testIdentity.Uid)
	assert.Equal(t, err, ErrNotExist)

	_, err = dm.GetPrivateKey(testIdentity.Uid)
	assert.Equal(t, err, ErrNotExist)

	_, err = dm.GetPublicKey(testIdentity.Uid)
	assert.Equal(t, err, ErrNotExist)

	_, err = dm.GetAuthToken(testIdentity.Uid)
	assert.Equal(t, err, ErrNotExist)

	// store identity
	err = dm.StoreNewIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	sig, err := dm.GetSignature(tx, testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, sig, testIdentity.Signature)

	priv, err := dm.GetPrivateKey(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, priv, testIdentity.PrivateKey)

	pub, err := dm.GetPublicKey(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, pub, testIdentity.PublicKey)

	auth, err := dm.GetAuthToken(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, auth, testIdentity.AuthToken)
}

func TestNewSqlDatabaseInfo_InvalidDSN(t *testing.T) {
	invalidDSN := "this is not a DSN"

	_, err := NewSqlDatabaseInfo(invalidDSN, testTableName, 0)
	assert.Error(t, err)
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

	err = dm.StoreNewIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// store same identity again
	tx2, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	err = dm.StoreNewIdentity(tx2, testIdentity)
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

	err = dm.StoreNewIdentity(tx, testIdentity)
	require.NoError(t, err)

	cancel()

	// check not exists
	_, err = dm.GetAuthToken(testIdentity.Uid)
	assert.Equal(t, err, ErrNotExist)
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
		go func(idx int, identity ent.Identity) {
			err := storeIdentity(dm, identity, wg)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", identity.Uid, err)
			}
		}(i, testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			err := checkIdentity(dm, id, wg)
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

type dbConfig struct {
	PostgresDSN string
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

	c := &dbConfig{}
	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			fmt.Print(fileCloseErr)
		}
		return nil, err
	}

	err = fileHandle.Close()
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

	dm, err := NewSqlDatabaseInfo(c.PostgresDSN, testTableName, 10)
	if err != nil {
		return nil, err
	}

	_, err = dm.db.Exec(CreateTable(PostgresIdentity, dm.tableName))
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

	dm.Close()
}

func generateRandomIdentity() ent.Identity {
	priv := make([]byte, 32)
	rand.Read(priv)

	pub := make([]byte, 64)
	rand.Read(pub)

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

	err = ctxManager.StoreNewIdentity(tx, id)
	if err != nil {
		return fmt.Errorf("StoreNewIdentity: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Commit: %v", err)
	}

	return nil
}

func checkIdentity(ctxManager ContextManager, id ent.Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	if err != nil {
		return err
	}

	sig, err := ctxManager.GetSignature(tx, id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig, id.Signature) {
		return fmt.Errorf("GetSignature returned unexpected value")
	}

	priv, err := ctxManager.GetPrivateKey(id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(priv, id.PrivateKey) {
		return fmt.Errorf("GetPrivateKey returned unexpected value")
	}

	pub, err := ctxManager.GetPublicKey(id.Uid)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, id.PublicKey) {
		return fmt.Errorf("GetPublicKey returned unexpected value")
	}

	auth, err := ctxManager.GetAuthToken(id.Uid)
	if err != nil {
		return err
	}
	if auth != id.AuthToken {
		return fmt.Errorf("GetAuthToken returned unexpected value")
	}

	return nil
}
