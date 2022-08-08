package repository

import (
	"context"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
)

var (
	testUid          = uuid.MustParse("b8869002-9d19-418a-94b0-83664843396f")
	testPrivKey, _   = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU0xUExBUEhvRU42Y0hVWlR5NkttSEFqa3NqSkJTbGEwUWdobkVxSnJPWHFvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFWTB0SjN6V1hXbzl3QWxxYkwrazdBSWdNV21iZnkvd0kxMUxTWWVVL2tnMlU5WENOM3hiTwpHSjE5M2o5NmhOTHprN3ZrZk9JMmJSc2gxTUpqWW5hRC93PT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=")
	testPubKey, _    = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWTB0SjN6V1hXbzl3QWxxYkwrazdBSWdNV21iZgp5L3dJMTFMU1llVS9rZzJVOVhDTjN4Yk9HSjE5M2o5NmhOTHprN3ZrZk9JMmJSc2gxTUpqWW5hRC93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==")
	testSignature, _ = base64.StdEncoding.DecodeString("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9HixkmBhVrYaB0NhtHpHgAWeTnLZpTSxCKs0gigByk5SH9pmQ==")
	testAuth         = "650YpEeEBF2H88Z88idG6Q=="

	testId = ent.Identity{
		Uid:        testUid,
		PrivateKey: testPrivKey,
		PublicKey:  testPubKey,
		Signature:  testSignature,
		AuthToken:  testAuth,
	}
)

func BenchmarkPostgres(b *testing.B) {
	dm, err := initDB(0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateSignature(b, dm)
	}
}

func BenchmarkSQLite(b *testing.B) {
	dm, err := NewDatabaseManager(SQLite, filepath.Join(b.TempDir(), testSQLiteDSN), 0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateSignature(b, dm)
	}
}

func BenchmarkPostgres_async(b *testing.B) {
	dm, err := initDB(0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg := &sync.WaitGroup{}
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				updateSignature(b, dm)
				wg.Done()
			}()
		}
		wg.Wait()
	}
}

func BenchmarkSQLite_async(b *testing.B) {
	dm, err := NewDatabaseManager(SQLite, filepath.Join(b.TempDir(), testSQLiteDSN), 0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg := &sync.WaitGroup{}
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				updateSignature(b, dm)
				wg.Done()
			}()
		}
		wg.Wait()
	}
}

func BenchmarkSQLite_config(b *testing.B) {
	sqliteWithNonDefaultConfig := testSQLiteDSN + "?_txlock=EXCLUSIVE" + // https://www.sqlite.org/lang_transaction.html
		"&_pragma=journal_mode(WAL)" + // https://www.sqlite.org/wal.html
		"&_pragma=synchronous(FULL)" + // https://www.sqlite.org/pragma.html#pragma_synchronous
		"&_pragma=wal_autocheckpoint(1)" + // checkpoint when WAL reaches x pages https://www.sqlite.org/pragma.html#pragma_wal_autocheckpoint
		"&_pragma=wal_checkpoint(PASSIVE)" + // https://www.sqlite.org/pragma.html#pragma_wal_checkpoint
		"&_pragma=journal_size_limit(1000)" + // max WAL file size in bytes https://www.sqlite.org/pragma.html#pragma_journal_size_limit
		"&_pragma=busy_timeout(100)" // https://www.sqlite.org/pragma.html#pragma_busy_timeout

	dm, err := NewDatabaseManager(SQLite, filepath.Join(b.TempDir(), sqliteWithNonDefaultConfig), 0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg := &sync.WaitGroup{}
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				updateSignature(b, dm)
				wg.Done()
			}()
		}
		wg.Wait()
	}
}

func storeTestIdentity(t require.TestingT, ctxManager ContextManager) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	require.NoError(t, err)

	err = ctxManager.StoreIdentity(tx, testId)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)
}

func updateSignature(t require.TestingT, ctxManager ContextManager) {
	_, err := ctxManager.LoadActiveFlag(testId.Uid)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	require.NoError(t, err)

	sig, err := ctxManager.LoadSignatureForUpdate(tx, testId.Uid)
	require.NoError(t, err)

	rand.Read(sig)

	err = ctxManager.StoreSignature(tx, testId.Uid, sig)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)
}
