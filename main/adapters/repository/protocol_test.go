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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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

	p, err := NewExtendedProtocol(&MockCtxMngr{
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

	_, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.Error(t, err)
}

func TestExtendedProtocol_StoreSignature(t *testing.T) {
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	ctxMngr := &MockCtxMngr{}
	p, err := NewExtendedProtocol(ctxMngr, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	err = p.StoreExternalIdentity(context.Background(), ent.ExternalIdentity{Uid: testUid, PublicKey: testPubKey})
	require.NoError(t, err)
	assert.Equal(t, testUid, ctxMngr.extId.Uid)
	assert.Equal(t, testPubKeyBytes, ctxMngr.extId.PublicKey)
}

func TestExtendedProtocol_LoadExternalIdentity(t *testing.T) {
	ctxMngr := &MockCtxMngr{extId: ent.ExternalIdentity{Uid: testUid, PublicKey: testPubKeyBytes}}
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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
	ctxMngr := &MockCtxMngr{}
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_Update(t *testing.T) {
	ctxMngr := &MockCtxMngr{}
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
	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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

	p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{SecretBytes32: testSecret})
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

func TestExtendedProtocol_VerifyBackendResponse(t *testing.T) {
	var (
		niomonUUID      = uuid.MustParse("9d3c78ff-22f3-4441-a5d1-85c636d486ff")
		niomonPubKey, _ = base64.StdEncoding.DecodeString("LnU8BkvGcZQPy5gWVUL+PHA0DP9dU61H8DBO8hZvTyI7lXIlG1/oruVMT7gS2nlZDK9QG+ugkRt/zTrdLrAYDA==")
		niomonIdentity  = &config.Identity{
			UUID:      niomonUUID,
			PublicKey: niomonPubKey,
		}
		testChainedUPP                = []byte{0x96, 0x23, 0xc4, 0x10, 0x63, 0xd9, 0x76, 0x84, 0x1a, 0x63, 0x44, 0xa8, 0x8f, 0xc2, 0x30, 0x16, 0xf8, 0x7c, 0x15, 0x4, 0xc4, 0x40, 0x5c, 0x16, 0xfe, 0x8d, 0xb3, 0x53, 0xb7, 0xee, 0x1c, 0xd4, 0xdb, 0x9e, 0x2c, 0xeb, 0xbf, 0xd6, 0xd1, 0x6b, 0x65, 0xfb, 0xf3, 0x62, 0xe9, 0x6e, 0x7d, 0x19, 0x62, 0x4c, 0xbb, 0xca, 0x45, 0x81, 0x7d, 0x73, 0x65, 0x59, 0x72, 0x7, 0xe0, 0x99, 0x36, 0x23, 0xc6, 0x74, 0xc5, 0xea, 0x31, 0x32, 0x7, 0xd0, 0xaf, 0x1a, 0x88, 0x24, 0x72, 0x75, 0x25, 0xef, 0x9c, 0x84, 0xc2, 0xc3, 0x37, 0xc6, 0x0, 0xc4, 0x20, 0x41, 0x2c, 0xf8, 0xec, 0xb7, 0xb9, 0x41, 0xaa, 0x2b, 0x71, 0x1d, 0x40, 0xab, 0x68, 0xc4, 0x69, 0x36, 0x25, 0xe, 0x76, 0x67, 0x41, 0xd6, 0xfa, 0xeb, 0x31, 0xc5, 0x9d, 0x6b, 0xb0, 0x20, 0xfb, 0xc4, 0x40, 0xe7, 0xe6, 0x3, 0x1d, 0xa8, 0x18, 0x53, 0x2d, 0x7c, 0x77, 0xab, 0x9b, 0x67, 0xb, 0x64, 0x54, 0x8e, 0xb3, 0xeb, 0x7b, 0xd9, 0x77, 0x7f, 0x9, 0xdd, 0x79, 0x52, 0x8f, 0x92, 0x84, 0x8d, 0x78, 0xf7, 0x2e, 0xd, 0x27, 0x68, 0x7f, 0xb5, 0xe4, 0x61, 0xf9, 0x7e, 0x77, 0xf0, 0xd9, 0xe9, 0x25, 0xc, 0xdb, 0x51, 0x87, 0x78, 0xf6, 0x1f, 0x8c, 0x8d, 0xfd, 0x5b, 0x21, 0xa, 0x87, 0x58, 0x60}
		testBckndRespUPP              = []byte{0x96, 0x23, 0xc4, 0x10, 0x9d, 0x3c, 0x78, 0xff, 0x22, 0xf3, 0x44, 0x41, 0xa5, 0xd1, 0x85, 0xc6, 0x36, 0xd4, 0x86, 0xff, 0xc4, 0x40, 0xe7, 0xe6, 0x3, 0x1d, 0xa8, 0x18, 0x53, 0x2d, 0x7c, 0x77, 0xab, 0x9b, 0x67, 0xb, 0x64, 0x54, 0x8e, 0xb3, 0xeb, 0x7b, 0xd9, 0x77, 0x7f, 0x9, 0xdd, 0x79, 0x52, 0x8f, 0x92, 0x84, 0x8d, 0x78, 0xf7, 0x2e, 0xd, 0x27, 0x68, 0x7f, 0xb5, 0xe4, 0x61, 0xf9, 0x7e, 0x77, 0xf0, 0xd9, 0xe9, 0x25, 0xc, 0xdb, 0x51, 0x87, 0x78, 0xf6, 0x1f, 0x8c, 0x8d, 0xfd, 0x5b, 0x21, 0xa, 0x87, 0x58, 0x60, 0x0, 0xc4, 0x20, 0xf3, 0x4c, 0xe3, 0x73, 0xd, 0xbf, 0x49, 0x9c, 0xac, 0x2b, 0xf8, 0x8, 0x7, 0xf, 0xd2, 0x8a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0x75, 0x12, 0xa2, 0x75, 0x26, 0xed, 0x6b, 0x9e, 0xb5, 0x97, 0xaa, 0x84, 0x39, 0x3a, 0xc3, 0x2d, 0x7c, 0x7b, 0xa5, 0x19, 0x38, 0x9c, 0xf3, 0xde, 0x3c, 0x30, 0xbc, 0x88, 0x4a, 0x7a, 0x29, 0xe1, 0x62, 0x7a, 0x91, 0xb4, 0x99, 0x20, 0xfe, 0x2c, 0xd, 0xc7, 0xaf, 0x95, 0x41, 0x9d, 0x30, 0x64, 0xf6, 0xa8, 0xc0, 0xf1, 0xea, 0x35, 0x4c, 0x33, 0x25, 0x91, 0x2c, 0x32, 0xca, 0x87, 0x55, 0xbb}
		testBckndRespUPP_badSignature = []byte{0x96, 0x23, 0xc4, 0x10, 0x9d, 0x3c, 0x78, 0xff, 0x22, 0xf3, 0x44, 0x41, 0xa5, 0xd1, 0x85, 0xc6, 0x36, 0xd4, 0x86, 0xff, 0xc4, 0x40, 0xe7, 0xe6, 0x3, 0x1d, 0xa8, 0x18, 0x53, 0x2d, 0x7c, 0x77, 0xab, 0x9b, 0x67, 0xb, 0x64, 0x54, 0x8e, 0xb3, 0xeb, 0x7b, 0xd9, 0x77, 0x7f, 0x9, 0xdd, 0x79, 0x52, 0x8f, 0x92, 0x84, 0x8d, 0x78, 0xf7, 0x2e, 0xd, 0x27, 0x68, 0x7f, 0xb5, 0xe4, 0x61, 0xf9, 0x7e, 0x77, 0xf0, 0xd9, 0xe9, 0x25, 0xc, 0xdb, 0x51, 0x87, 0x78, 0xf6, 0x1f, 0x8c, 0x8d, 0xfd, 0x5b, 0x21, 0xa, 0x87, 0x58, 0x60, 0x0, 0xc4, 0x20, 0xf3, 0x4c, 0xe3, 0x73, 0xd, 0xbf, 0x49, 0x9c, 0xac, 0x2b, 0xf8, 0x8, 0x7, 0xf, 0xd2, 0x8a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0xe7, 0xe6, 0x3, 0x1d, 0xa8, 0x18, 0x53, 0x2d, 0x7c, 0x77, 0xab, 0x9b, 0x67, 0xb, 0x64, 0x54, 0x8e, 0xb3, 0xeb, 0x7b, 0xd9, 0x77, 0x7f, 0x9, 0xdd, 0x79, 0x52, 0x8f, 0x92, 0x84, 0x8d, 0x78, 0xf7, 0x2e, 0xd, 0x27, 0x68, 0x7f, 0xb5, 0xe4, 0x61, 0xf9, 0x7e, 0x77, 0xf0, 0xd9, 0xe9, 0x25, 0xc, 0xdb, 0x51, 0x87, 0x78, 0xf6, 0x1f, 0x8c, 0x8d, 0xfd, 0x5b, 0x21, 0xa, 0x87, 0x58, 0x60}
		testBckndRespUPP_notChained   = []byte{0x95, 0x22, 0xc4, 0x10, 0x9d, 0x3c, 0x78, 0xff, 0x22, 0xf3, 0x44, 0x41, 0xa5, 0xd1, 0x85, 0xc6, 0x36, 0xd4, 0x86, 0xff, 0x0, 0xc4, 0x20, 0x9a, 0x1e, 0xf1, 0x4a, 0x6b, 0x23, 0x4a, 0xa9, 0x8e, 0x75, 0xe5, 0xe0, 0x55, 0x95, 0x99, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0x55, 0xdd, 0xa0, 0x21, 0xe4, 0x4f, 0x11, 0x31, 0x93, 0x2f, 0x9c, 0x34, 0x3, 0xf6, 0xad, 0xfa, 0xe7, 0x62, 0xd5, 0xe4, 0x3d, 0x95, 0x94, 0x40, 0x56, 0x1f, 0x35, 0x3b, 0xd, 0x1d, 0x5d, 0xb, 0xc3, 0x1a, 0x29, 0xb8, 0x8a, 0x8f, 0xa6, 0x5f, 0x84, 0xc8, 0x21, 0xec, 0xb3, 0xdf, 0xc5, 0x70, 0x38, 0x83, 0x43, 0xaa, 0xa1, 0x23, 0x50, 0xc, 0x39, 0x45, 0xa, 0x5a, 0xf6, 0x2e, 0x86, 0xed}
		testBckndRespUPP_badChain     = []byte{0x96, 0x23, 0xc4, 0x10, 0x9d, 0x3c, 0x78, 0xff, 0x22, 0xf3, 0x44, 0x41, 0xa5, 0xd1, 0x85, 0xc6, 0x36, 0xd4, 0x86, 0xff, 0xc4, 0x40, 0xfa, 0x91, 0x3c, 0xb8, 0x45, 0x56, 0x79, 0xfd, 0xf9, 0x33, 0xd5, 0xc0, 0x57, 0x28, 0xb6, 0xab, 0x55, 0xb3, 0x6, 0x29, 0xc1, 0x56, 0x82, 0x4a, 0xaa, 0x43, 0x59, 0xd1, 0x7d, 0x9c, 0x4b, 0xf5, 0x60, 0x8c, 0x38, 0x22, 0xa9, 0x63, 0xa2, 0x42, 0x2c, 0x9d, 0x1e, 0x78, 0x99, 0x63, 0xa7, 0x90, 0x2c, 0x69, 0x1f, 0x63, 0xc2, 0x73, 0x9a, 0xab, 0xc6, 0x79, 0xf, 0x36, 0x95, 0x2a, 0x52, 0x8, 0x0, 0xc4, 0x20, 0x10, 0xc4, 0x1a, 0xae, 0xb9, 0xc5, 0x40, 0x67, 0x97, 0x8f, 0xbe, 0x26, 0x91, 0x99, 0x17, 0x5a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0xee, 0xa2, 0x5d, 0x83, 0x35, 0x34, 0xc1, 0xe7, 0xaa, 0x2, 0x1a, 0x36, 0x8a, 0x20, 0x40, 0xc1, 0x99, 0xfe, 0xe4, 0xab, 0x5a, 0xf, 0xac, 0x94, 0x88, 0xb0, 0xeb, 0xb9, 0x71, 0x2c, 0xa8, 0x5f, 0x75, 0xb0, 0x33, 0xe2, 0xf0, 0x7c, 0x4, 0x1d, 0xbc, 0x71, 0x32, 0x4b, 0x5d, 0xc0, 0x66, 0xab, 0xf0, 0xf5, 0xa8, 0xfb, 0x14, 0x36, 0x52, 0xc8, 0x7e, 0x2c, 0x2d, 0x87, 0xdd, 0x59, 0xc0, 0xe9}
	)

	testCases := []struct {
		name                              string
		verifyNiomonResponse              bool
		niomonId                          *config.Identity
		checkConstructorError             func(*testing.T, error)
		requestUPP                        []byte
		responseUPP                       []byte
		checkVerifyBackendResponseResults func(*testing.T, bool, bool, error)
	}{
		{
			name:                 "happy path",
			verifyNiomonResponse: true,
			niomonId:             niomonIdentity,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			requestUPP:  testChainedUPP,
			responseUPP: testBckndRespUPP,
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.NoError(t, err)
				assert.True(t, chainOk)
				assert.True(t, signatureOk)
			},
		},
		{
			name:                 "disable backend response verification",
			verifyNiomonResponse: false,
			niomonId:             nil,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.NoError(t, err)
				assert.False(t, chainOk)
				assert.False(t, signatureOk)
			},
		},
		{
			name:                 "niomon identity is nil pointer",
			verifyNiomonResponse: true,
			niomonId:             nil,
			checkConstructorError: func(t *testing.T, err error) {
				assert.EqualError(t, err, "config field NiomonIdentity is nil pointer")
			},
		},
		{
			name:                 "set invalid verification key",
			verifyNiomonResponse: true,
			niomonId: &config.Identity{
				UUID:      niomonUUID,
				PublicKey: []byte("invalid verification key"),
			},
			checkConstructorError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid backend response verification key [bytes]")
			},
		},
		{
			name:                 "invalid backend response signature",
			verifyNiomonResponse: true,
			niomonId:             niomonIdentity,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			requestUPP:  testChainedUPP,
			responseUPP: testBckndRespUPP_badSignature,
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.Error(t, err)
				assert.EqualError(t, err, fmt.Sprintf("backend response signature verification failed with public key: %s", base64.StdEncoding.EncodeToString(niomonPubKey)))
				assert.False(t, chainOk)
				assert.False(t, signatureOk)
			},
		},
		{
			name:                 "invalid backend response",
			verifyNiomonResponse: true,
			niomonId:             niomonIdentity,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			requestUPP:  testChainedUPP,
			responseUPP: []byte("timeout"),
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.Error(t, err)
				assert.EqualError(t, err, "response from UBIRCH Trust Service is not a UPP: \"timeout\"")
				assert.False(t, chainOk)
				assert.False(t, signatureOk)
			},
		},
		{
			name:                 "backend response not chained",
			verifyNiomonResponse: true,
			niomonId:             niomonIdentity,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			requestUPP:  testChainedUPP,
			responseUPP: testBckndRespUPP_notChained,
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.NoError(t, err)
				assert.False(t, chainOk)
				assert.True(t, signatureOk)
			},
		},
		{
			name:                 "invalid backend response chain",
			verifyNiomonResponse: true,
			niomonId:             niomonIdentity,
			checkConstructorError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			requestUPP:  testChainedUPP,
			responseUPP: testBckndRespUPP_badChain,
			checkVerifyBackendResponseResults: func(t *testing.T, signatureOk, chainOk bool, err error) {
				assert.Error(t, err)
				assert.EqualError(t, err, "backend response chain check failed")
				assert.False(t, chainOk)
				assert.True(t, signatureOk)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewExtendedProtocol(&MockCtxMngr{}, &config.Config{
				SecretBytes32:        testSecret,
				VerifyNiomonResponse: c.verifyNiomonResponse,
				NiomonIdentity:       c.niomonId,
			})
			c.checkConstructorError(t, err)
			if err != nil {
				return
			}

			signatureOk, chainOk, err := p.VerifyBackendResponse(c.requestUPP, c.responseUPP)
			c.checkVerifyBackendResponseResults(t, signatureOk, chainOk, err)
		})
	}
}
