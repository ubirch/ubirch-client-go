package database

import (
	"context"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
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
	dm, err := initSQLiteDB(b, 0)
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
				defer wg.Done()
				updateSignature(b, dm)
			}()
		}
		wg.Wait()
	}
}

func BenchmarkSQLite_async(b *testing.B) {
	dm, err := initSQLiteDB(b, 0)
	require.NoError(b, err)
	defer cleanUpDB(b, dm)

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg := &sync.WaitGroup{}
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateSignature(b, dm)
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

	dsn := filepath.Join(b.TempDir(), sqliteWithNonDefaultConfig)
	dm, err := NewDatabaseManager(SQLite, dsn, 0)
	require.NoError(b, err)
	defer cleanUpDB(b, &extendedDatabaseManager{
		DatabaseManager: dm,
		dsn:             dsn,
	})

	storeTestIdentity(b, dm)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg := &sync.WaitGroup{}
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateSignature(b, dm)
			}()
		}
		wg.Wait()
	}
}

func storeTestIdentity(t require.TestingT, ctxManager repository.ContextManager) {
	testId := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := ctxManager.StartTransaction(ctx)
	require.NoError(t, err)

	err = ctxManager.StoreIdentity(tx, testId)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)
}

func updateSignature(t require.TestingT, ctxManager repository.ContextManager) {
	testId := getTestIdentity()

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
