package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	pw "github.com/ubirch/ubirch-client-go/main/adapters/password-hashing"
)

var (
	testSecret, _ = base64.StdEncoding.DecodeString("ZQJt1OC9+4OZtgZLLT9mX25BbrZdxtOQBjK4GyRF2fQ=")

	testUid          = uuid.MustParse("b8869002-9d19-418a-94b0-83664843396f")
	testPrivKey      = []byte("-----BEGIN PRIVATE KEY-----\nMHcCAQEEILagfFV70hVPpY1L5pIkWu3mTZisQ1yCmfhKL5vrGQfOoAoGCCqGSM49\nAwEHoUQDQgAEoEOfFKZ2U+r7L3CqCArZ63IyB83zqByp8chT07MeXLBx9WMYsaqn\nb38qXThsEnH7WwSwA/eRKjm9SbR6cve4Mg==\n-----END PRIVATE KEY-----\n")
	testPubKey       = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoEOfFKZ2U+r7L3CqCArZ63IyB83z\nqByp8chT07MeXLBx9WMYsaqnb38qXThsEnH7WwSwA/eRKjm9SbR6cve4Mg==\n-----END PUBLIC KEY-----\n")
	testPubKeyBytes  = []byte{0xa0, 0x43, 0x9f, 0x14, 0xa6, 0x76, 0x53, 0xea, 0xfb, 0x2f, 0x70, 0xaa, 0x08, 0x0a, 0xd9, 0xeb, 0x72, 0x32, 0x07, 0xcd, 0xf3, 0xa8, 0x1c, 0xa9, 0xf1, 0xc8, 0x53, 0xd3, 0xb3, 0x1e, 0x5c, 0xb0, 0x71, 0xf5, 0x63, 0x18, 0xb1, 0xaa, 0xa7, 0x6f, 0x7f, 0x2a, 0x5d, 0x38, 0x6c, 0x12, 0x71, 0xfb, 0x5b, 0x04, 0xb0, 0x03, 0xf7, 0x91, 0x2a, 0x39, 0xbd, 0x49, 0xb4, 0x7a, 0x72, 0xf7, 0xb8, 0x32}
	testSignature, _ = base64.StdEncoding.DecodeString("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9HixkmBhVrYaB0NhtHpHgAWeTnLZpTSxCKs0gigByk5SH9pmQ==")
	testAuth         = "650YpEeEBF2H88Z88idG6Q=="
)

func TestProtocol(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	testIdentity := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check not exists
	exists, err := p.IsInitialized(testIdentity.Uid)
	require.NoError(t, err)
	assert.False(t, exists)

	_, err = p.LoadPrivateKey(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = p.LoadPublicKey(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	exists, err = p.IsInitialized(testIdentity.Uid)
	require.NoError(t, err)
	assert.True(t, exists)

	priv, err := p.LoadPrivateKey(testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.PrivateKey, priv)

	pub, err := p.LoadPublicKey(testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.PublicKey, pub)

	ok, found, err := p.CheckAuth(context.Background(), testIdentity.Uid, testIdentity.AuthToken)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_LoadPrivateKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	priv, err := p.LoadPrivateKey(i.Uid)
	require.NoError(t, err)
	assert.Equal(t, i.PrivateKey, priv)
}

func TestExtendedProtocol_LoadPublicKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	pub, err := p.LoadPublicKey(i.Uid)
	require.NoError(t, err)
	assert.Equal(t, i.PublicKey, pub)
}

func TestExtendedProtocol_LoadPublicKeyFromExternalIdentity(t *testing.T) {
	extId := ent.ExternalIdentity{Uid: testUid, PublicKey: testPubKeyBytes}

	p, err := NewExtendedProtocol(&mockCtxMngr{
		extId: extId,
	}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	pub, err := p.LoadPublicKey(extId.Uid)
	require.NoError(t, err)
	assert.Equal(t, testPubKey, pub)
}

func TestNewExtendedProtocol_BadSecret(t *testing.T) {
	badSecret := make([]byte, 31)
	rand.Read(badSecret)

	conf := &config.Config{
		SecretBytes32: badSecret,
	}

	_, err := NewExtendedProtocol(&mockCtxMngr{}, conf)
	require.Error(t, err)
}

func TestExtendedProtocol_StoreSignature(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	testIdentity := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	newSignature := make([]byte, p.SignatureLength())
	rand.Read(newSignature)

	tx, err = p.StartTransaction(ctx)
	require.NoError(t, err)

	sig, err := p.LoadSignatureForUpdate(tx, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, testIdentity.Signature, sig)

	err = p.StoreSignature(tx, testIdentity.Uid, newSignature)
	require.NoError(t, err)

	tx2, err := p.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	sig, err = p.LoadSignatureForUpdate(tx2, testIdentity.Uid)
	require.NoError(t, err)
	assert.Equal(t, newSignature, sig)
}

func TestExtendedProtocol_BadStoreSignature(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	testIdentity := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	newSignature := make([]byte, p.SignatureLength()-1)
	rand.Read(newSignature)

	tx, err = p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreSignature(tx, testIdentity.Uid, newSignature)
	require.Error(t, err)
}

func Test_StoreNewIdentity_BadUUID(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.Uid = uuid.Nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPrivateKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.PrivateKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPrivateKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.PrivateKey = []byte("bad private key")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.PublicKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.PublicKey = []byte("bad public key")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadSignature(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.Signature = make([]byte, p.SignatureLength()+1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadAuth(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()
	i.AuthToken = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func TestExtendedProtocol_StoreExternalIdentity(t *testing.T) {
	ctxMngr := &mockCtxMngr{}
	p, err := NewExtendedProtocol(ctxMngr, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	err = p.StoreExternalIdentity(context.Background(), ent.ExternalIdentity{Uid: testUid, PublicKey: testPubKey})
	require.NoError(t, err)
	assert.Equal(t, testUid, ctxMngr.extId.Uid)
	assert.Equal(t, testPubKeyBytes, ctxMngr.extId.PublicKey)
}

func TestExtendedProtocol_LoadExternalIdentity(t *testing.T) {
	ctxMngr := &mockCtxMngr{extId: ent.ExternalIdentity{Uid: testUid, PublicKey: testPubKeyBytes}}
	p, err := NewExtendedProtocol(ctxMngr, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	extId, err := p.LoadExternalIdentity(context.Background(), testUid)
	require.NoError(t, err)
	assert.Equal(t, testUid, extId.Uid)
	assert.Equal(t, testPubKey, extId.PublicKey)

	cachedKey, err := p.keyCache.GetPublicKey(testUid)
	require.NoError(t, err)
	assert.Equal(t, testPubKey, cachedKey)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.AuthToken)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid_Cached(t *testing.T) {
	ctxMngr := &mockCtxMngr{}
	p, err := NewExtendedProtocol(ctxMngr, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	p.authCache.Store(i.Uid, ctxMngr.id.AuthToken)

	ok, found, err := p.CheckAuth(ctx, i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_NotFound(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Update(t *testing.T) {
	ctxMngr := &mockCtxMngr{}
	testConf := &config.Config{
		SecretBytes32:  testSecret,
		KdUpdateParams: true,
	}

	p, err := NewExtendedProtocol(ctxMngr, testConf)
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	pwHashPreUpdate := ctxMngr.id.AuthToken
	p.pwHasher.Params = pw.GetArgon2idParams(pw.DefaultMemory, pw.DefaultTime,
		2*pw.DefaultParallelism, pw.DefaultKeyLen, pw.DefaultSaltLen)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.AuthToken)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)

	assert.NotEqual(t, pwHashPreUpdate, ctxMngr.id.AuthToken)

	ok, found, err = p.CheckAuth(ctx, i.Uid, i.AuthToken)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_AuthCache(t *testing.T) {
	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	i := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(ctx, i.Uid, i.AuthToken)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, ok)

	cachedAuth, found := p.authCache.Load(i.Uid)
	require.True(t, found)
	assert.Equal(t, i.AuthToken, cachedAuth.(string))
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	p, err := NewExtendedProtocol(&mockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	testIdentity := getTestIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// repeatedly check same identity to test cache
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			err := checkIdentity(p, testIdentity, wg)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func getTestIdentity() ent.Identity {
	return ent.Identity{
		Uid:        testUid,
		PrivateKey: testPrivKey,
		PublicKey:  testPubKey,
		Signature:  testSignature,
		AuthToken:  testAuth,
	}
}

func storeIdentity(ctxManager ContextManager, id ent.Identity) error {
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

func checkAuth(auth, authToCheck string) error {
	pwHasher := &pw.Argon2idKeyDerivator{}

	_, ok, err := pwHasher.CheckPassword(context.Background(), auth, authToCheck)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("LoadAuth returned unexpected value")
	}
	return nil
}

func checkIdentity(ctxManager ContextManager, id ent.Identity, wg *sync.WaitGroup) error {
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

	err = checkAuth(fetchedId.AuthToken, id.AuthToken)
	if err != nil {
		return fmt.Errorf("checkAuth: %v", err)
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

type mockCtxMngr struct {
	id    ent.Identity
	extId ent.ExternalIdentity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (TransactionCtx, error) {
	return &mockTx{
		idBuf: ent.Identity{},
		id:    &m.id,
	}, nil
}

func (m *mockCtxMngr) StoreIdentity(t TransactionCtx, id ent.Identity) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}
	tx.idBuf = id

	return nil
}

func (m *mockCtxMngr) LoadIdentity(u uuid.UUID) (ent.Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return ent.Identity{}, ErrNotExist
	}
	id := m.id
	return id, nil
}

func (m *mockCtxMngr) StoreActiveFlag(t TransactionCtx, u uuid.UUID, a bool) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.Active = a
	return nil
}

func (m *mockCtxMngr) LoadActiveFlagForUpdate(t TransactionCtx, u uuid.UUID) (bool, error) {
	tx, ok := t.(*mockTx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return false, ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.Active, nil
}

func (m *mockCtxMngr) LoadActiveFlag(u uuid.UUID) (bool, error) {
	return m.id.Active, nil
}

func (m *mockCtxMngr) StoreSignature(t TransactionCtx, u uuid.UUID, s []byte) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.Signature = s
	return nil
}

func (m *mockCtxMngr) LoadSignatureForUpdate(t TransactionCtx, u uuid.UUID) ([]byte, error) {
	tx, ok := t.(*mockTx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.Signature, nil
}

func (m *mockCtxMngr) StoreAuth(t TransactionCtx, u uuid.UUID, a string) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.AuthToken = a
	return nil
}

func (m *mockCtxMngr) LoadAuthForUpdate(t TransactionCtx, u uuid.UUID) (string, error) {
	tx, ok := t.(*mockTx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return "", ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.AuthToken, nil
}

func (m *mockCtxMngr) StoreExternalIdentity(ctx context.Context, externalId ent.ExternalIdentity) error {
	m.extId = externalId
	return nil
}

func (m *mockCtxMngr) LoadExternalIdentity(ctx context.Context, u uuid.UUID) (ent.ExternalIdentity, error) {
	if m.extId.Uid == uuid.Nil || m.extId.Uid != u {
		return ent.ExternalIdentity{}, ErrNotExist
	}
	return m.extId, nil
}

func (m *mockCtxMngr) GetIdentityUUIDs() ([]uuid.UUID, error) {
	return []uuid.UUID{m.id.Uid}, nil
}

func (m *mockCtxMngr) GetExternalIdentityUUIDs() ([]uuid.UUID, error) {
	return []uuid.UUID{m.extId.Uid}, nil
}

func (m *mockCtxMngr) IsReady() error {
	return nil
}

func (m *mockCtxMngr) Close() error {
	return nil
}

type mockTx struct {
	idBuf ent.Identity
	id    *ent.Identity
}

var _ TransactionCtx = (*mockTx)(nil)

func (m *mockTx) Commit() error {
	*m.id = m.idBuf
	*m = mockTx{}
	return nil
}

func (m *mockTx) Rollback() error {
	*m = mockTx{}
	return nil
}

type MockKeystorer struct {
	priv []byte
	pub  []byte
}

var _ ubirch.Keystorer = (*MockKeystorer)(nil)

func (m *MockKeystorer) GetIDs() ([]uuid.UUID, error) {
	panic("implement me")
}

func (m *MockKeystorer) PrivateKeyExists(id uuid.UUID) (bool, error) {
	if len(m.priv) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	if len(m.priv) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.priv, nil
}

func (m *MockKeystorer) SetPrivateKey(id uuid.UUID, key []byte) error {
	m.priv = key
	return nil
}

func (m *MockKeystorer) PublicKeyExists(id uuid.UUID) (bool, error) {
	if len(m.pub) == 0 {
		return false, nil
	}
	return true, nil
}

func (m *MockKeystorer) GetPublicKey(id uuid.UUID) ([]byte, error) {
	if len(m.pub) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	return m.pub, nil
}

func (m *MockKeystorer) SetPublicKey(id uuid.UUID, key []byte) error {
	m.pub = key
	return nil
}
