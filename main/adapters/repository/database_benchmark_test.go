package repository

import (
	"context"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"math/rand"
	"path/filepath"
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
