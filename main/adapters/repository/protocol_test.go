package repository

import (
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
			err := checkIdentity(p, testIdentity, protocolCheckAuth, wg)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB(0)
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	p, err := NewExtendedProtocol(dm, &config.Config{SecretBytes32: testSecret})
	require.NoError(t, err)

	// generate identities
	var testIdentities []ent.Identity
	for i := 0; i < testLoad/10; i++ {
		testId := getTestIdentity()
		testId.Uid = uuid.New()

		testIdentities = append(testIdentities, testId)
	}

	// store identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			defer wg.Done()

			err := storeIdentity(p, id)
			if err != nil {
				t.Errorf("%s: identity could not be stored: %v", id.Uid, err)
			}
		}(testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			err := checkIdentity(p, id, protocolCheckAuth, wg)
			if err != nil {
				t.Errorf("%s: %v", id.Uid, err)
			}
		}(testId)
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

func protocolCheckAuth(auth, authToCheck string) error {
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
