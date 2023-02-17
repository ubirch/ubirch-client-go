package database

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	testLoad = 100
)

var (
	testUid          = uuid.MustParse("b8869002-9d19-418a-94b0-83664843396f")
	testPrivKey      = []byte("-----BEGIN PRIVATE KEY-----\nMHcCAQEEILagfFV70hVPpY1L5pIkWu3mTZisQ1yCmfhKL5vrGQfOoAoGCCqGSM49\nAwEHoUQDQgAEoEOfFKZ2U+r7L3CqCArZ63IyB83zqByp8chT07MeXLBx9WMYsaqn\nb38qXThsEnH7WwSwA/eRKjm9SbR6cve4Mg==\n-----END PRIVATE KEY-----\n")
	testPubKey       = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoEOfFKZ2U+r7L3CqCArZ63IyB83z\nqByp8chT07MeXLBx9WMYsaqnb38qXThsEnH7WwSwA/eRKjm9SbR6cve4Mg==\n-----END PUBLIC KEY-----\n")
	testSignature, _ = base64.StdEncoding.DecodeString("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9HixkmBhVrYaB0NhtHpHgAWeTnLZpTSxCKs0gigByk5SH9pmQ==")
	testAuth         = "650YpEeEBF2H88Z88idG6Q=="
)

func TestDatabaseManager(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check not exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

	_, err = dm.LoadActiveFlag(testIdentity.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	_, err = dm.LoadActiveFlagForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

	_, err = dm.LoadSignatureForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

	_, err = dm.LoadAuthForUpdate(tx, testIdentity.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

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
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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

	err = dm.StoreActiveFlag(tx, testIdentity.Uid, false)
	require.NoError(t, err)

	active, err = dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, active)

	err = tx.Commit()
	require.NoError(t, err)

	active, err = dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, active)

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreActiveFlag(tx, testIdentity.Uid, true)
	require.NoError(t, err)

	active, err = dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, active)

	err = tx.Commit()
	require.NoError(t, err)

	active, err = dm.LoadActiveFlag(testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, active)
}

func TestDatabaseManager_SetSignature(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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

func TestDatabaseManager_Ready(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	err = dm.IsReady()
	require.NoError(t, err)
}

func TestDatabaseManager_NotReady(t *testing.T) {
	t.SkipNow()
	// this test takes over two minutes before running into a timeout
	if testing.Short() {
		t.Skipf("skipping long running test %s in short mode", t.Name())
	}

	// use DSN that is valid, but not reachable
	unreachableDSN := "postgres://nousr:nopwd@198.51.100.1:5432/nodatabase"

	_, err := NewDatabaseManager(PostgreSQL, unreachableDSN, &ConnectionParams{})
	assert.EqualError(t, err, "dial tcp 198.51.100.1:5432: connect: connection timed out")
}

func TestDatabaseManager_StoreExisting(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testIdentity := getTestIdentity()

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
	assert.Equal(t, repository.ErrNotExist, err)

	// make sure identity can be stored now
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	tx, err = dm.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	err = dm.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check identity exists
	_, err = dm.LoadIdentity(testIdentity.Uid)
	require.NoError(t, err)
}

func TestDatabaseManager_StartTransaction(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(1)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tx, err := dm.StartTransaction(ctx)
	require.NoError(t, err)
	assert.NotNil(t, tx)

	_, err = dm.StartTransaction(ctx)
	assert.EqualError(t, err, "context deadline exceeded")
}

func TestDatabaseManager_InvalidTransactionCtx(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	i := ent.Identity{}
	mockCtx := &repository.MockTx{}

	err = dm.StoreIdentity(mockCtx, i)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	err = dm.StoreActiveFlag(mockCtx, i.Uid, false)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	_, err = dm.LoadActiveFlagForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	err = dm.StoreSignature(mockCtx, i.Uid, nil)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	_, err = dm.LoadSignatureForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	err = dm.StoreAuth(mockCtx, i.Uid, "")
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")

	_, err = dm.LoadAuthForUpdate(mockCtx, i.Uid)
	assert.EqualError(t, err, "transactionCtx for database manager is not of expected type *TX")
}

func TestDatabaseLoad(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	wg := &sync.WaitGroup{}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// generate identities
	var testIdentities []ent.Identity
	for i := 0; i < testLoad; i++ {
		id := getTestIdentity()
		id.Uid = uuid.New()
		testIdentities = append(testIdentities, id)
	}

	// store identities
	for i, testId := range testIdentities {
		wg.Add(1)
		go func(idx int, id ent.Identity) {
			defer wg.Done()

			err := storeIdentity(dm, id)
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
			err := checkIdentity(dm, id, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()
}

func TestDatabaseManager_Retry(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(101)
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
				if strings.Contains(err.Error(), "55P03") ||
					strings.Contains(err.Error(), "53300") ||
					strings.Contains(err.Error(), "53400") {
					return
				}
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestDatabaseManager_StoreExternalIdentity(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testExtId := ent.ExternalIdentity{
		Uid:       uuid.New(),
		PublicKey: make([]byte, 64),
	}
	rand.Read(testExtId.PublicKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = dm.LoadExternalIdentity(ctx, testExtId.Uid)
	assert.Equal(t, repository.ErrNotExist, err)

	err = dm.StoreExternalIdentity(ctx, testExtId)
	require.NoError(t, err)

	err = dm.StoreExternalIdentity(ctx, testExtId)
	assert.Error(t, err)

	storedExtId, err := dm.LoadExternalIdentity(ctx, testExtId.Uid)
	require.NoError(t, err)
	assert.Equal(t, storedExtId.Uid, testExtId.Uid)
	assert.Equal(t, storedExtId.PublicKey, testExtId.PublicKey)

	cancel()

	err = dm.StoreExternalIdentity(ctx, testExtId)
	assert.EqualError(t, err, "context canceled")

	_, err = dm.LoadExternalIdentity(ctx, testExtId.Uid)
	assert.EqualError(t, err, "context canceled")
}

func TestDatabaseManager_GetIdentityUUIDs(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// generate and store identities for testing
	var testUUIDs []uuid.UUID
	for i := 0; i < 10; i++ {
		testId := getTestIdentity()
		testId.Uid = uuid.New()

		err = storeIdentity(dm, testId)
		require.NoError(t, err)

		testUUIDs = append(testUUIDs, testId.Uid)
	}

	ids, err := dm.GetIdentityUUIDs()
	require.NoError(t, err)

	assert.Equal(t, len(testUUIDs), len(ids))

	for _, id := range testUUIDs {
		assert.Contains(t, ids, id)
	}
}

func TestDatabaseManager_GetExternalIdentityUUIDs(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	// generate and store external identities for testing
	var testExtUUIDs []uuid.UUID
	for i := 0; i < 10; i++ {
		testExtId := ent.ExternalIdentity{
			Uid:       uuid.New(),
			PublicKey: make([]byte, 64),
		}

		err = dm.StoreExternalIdentity(context.TODO(), testExtId)
		require.NoError(t, err)

		testExtUUIDs = append(testExtUUIDs, testExtId.Uid)
	}

	ids, err := dm.GetExternalIdentityUUIDs()
	require.NoError(t, err)

	assert.Equal(t, len(testExtUUIDs), len(ids))

	for _, id := range testExtUUIDs {
		assert.Contains(t, ids, id)
	}
}

func TestDatabaseManager_NewDatabaseManager_DatabaseAlreadyOnLatestVersion(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	// migrate database schema to the latest version
	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = db.AutoMigrate(&ent.Identity{})
	require.NoError(t, err)

	dm, err := NewDatabaseManager(PostgreSQL, c.DbDSN, &ConnectionParams{})
	assert.NoError(t, err)

	cleanUpDB(t, &extendedDatabaseManager{
		DatabaseManager: dm,
		dsn:             c.DbDSN,
		driver:          PostgreSQL,
	})
}

//func TestDatabaseManager_NewDatabaseManager_DatabaseAlreadyExists(t *testing.T) {
//	// this test communicates with the actual postgres database
//	if testing.Short() {
//		t.Skipf("skipping integration test %s in short mode", t.Name())
//	}
//
//	c, err := getConfig()
//	require.NoError(t, err)
//
//	// migrate database schema to the latest version
//	err = migrateTo(PostgreSQL, c.DbDSN, 1)
//	require.NoError(t, err)
//
//	dm, err := NewDatabaseManager(PostgreSQL, c.DbDSN, &ConnectionParams{})
//	assert.NoError(t, err)
//
//	cleanUpDB(t, &extendedDatabaseManager{
//		DatabaseManager: dm,
//		dsn:             c.DbDSN,
//		driver:          PostgreSQL,
//	})
//}

func getConfig() (*config.Config, error) {
	configFileName := "config_test.json"
	fileHandle, err := os.Open(filepath.Join("../../", configFileName))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v \n"+
			"--------------------------------------------------------------------------------\n"+
			"Please provide a configuration file \"%s\" in the main directory which contains\n"+
			"a DSN for a postgres database in order to test the database context management.\n\n"+
			"!!! THIS MUST BE DIFFERENT FROM THE DSN USED FOR THE ACTUAL CONTEXT !!!\n\n"+
			"{\n\t\"dbDSN\": \"postgres://<username>:<password>@<hostname>:5432/<TEST-database>\"\n}\n"+
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

	if len(c.DbDSN) == 0 {
		return nil, fmt.Errorf("missing DSN for test postgres database ('dbDSN') in configuration %s", configFileName)
	}

	return c, nil
}

type extendedDatabaseManager struct {
	*DatabaseManager
	dsn    string
	driver string
}

func initDB(maxConns int) (*extendedDatabaseManager, error) {
	c, err := getConfig()
	if err != nil {
		return nil, err
	}

	dm, err := NewDatabaseManager(PostgreSQL, c.DbDSN, &ConnectionParams{MaxOpenConns: maxConns})
	if err != nil {
		return nil, err
	}

	return &extendedDatabaseManager{
		DatabaseManager: dm,
		dsn:             c.DbDSN,
		driver:          PostgreSQL,
	}, nil
}

func cleanUpDB(t assert.TestingT, dm *extendedDatabaseManager) {
	if dm.driver == SQLite {
		time.Sleep(5 * time.Millisecond) // this is here because we are getting SQLITE_BUSY error otherwise
	}

	tables, err := dm.db.Migrator().GetTables()

	for _, table := range tables {
		err = dm.db.Migrator().DropTable(table)
		assert.NoError(t, err)
	}

	err = dm.Close()
	assert.NoError(t, err)
}

func getTestIdentity() ent.Identity {
	return ent.Identity{
		Uid:        testUid,
		PrivateKey: testPrivKey,
		PublicKey:  testPubKey,
		Signature:  testSignature,
		AuthToken:  testAuth,
		Active:     true,
	}
}

func storeIdentity(ctxManager repository.ContextManager, id ent.Identity) error {
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

func checkIdentity(ctxManager repository.ContextManager, id ent.Identity, wg *sync.WaitGroup) error {
	defer wg.Done()

	fetchedId, err := ctxManager.LoadIdentity(id.Uid)
	if err != nil {
		return fmt.Errorf("LoadIdentity: %v", err)
	}

	if fetchedId.Uid != id.Uid {
		return fmt.Errorf("unexpected uuid")
	}

	if !bytes.Equal(fetchedId.PrivateKey, id.PrivateKey) {
		return fmt.Errorf("unexpected private key")
	}

	if !bytes.Equal(fetchedId.PublicKey, id.PublicKey) {
		return fmt.Errorf("unexpected public key")
	}

	if !bytes.Equal(fetchedId.Signature, id.Signature) {
		return fmt.Errorf("unexpected signature")
	}

	if fetchedId.AuthToken != id.AuthToken {
		return fmt.Errorf("unexpected auth token")
	}

	if fetchedId.Active != id.Active {
		return fmt.Errorf("unexpected active flag")
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
