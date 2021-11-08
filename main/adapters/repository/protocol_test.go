package repository

import (
	"context"
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

func TestProtocol(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// check not exists
	exists, err := p.IsInitialized(testIdentity.Uid)
	assert.NoError(t, err)
	assert.False(t, exists)

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	_, err = p.LoadSignature(tx, testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	err = tx.Commit()
	assert.NoError(t, err)

	_, err = p.LoadPrivateKey(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = p.LoadPublicKey(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	_, err = p.LoadAuthToken(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	// store identity
	tx, err = p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, testIdentity)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	// check exists
	exists, err = p.IsInitialized(testIdentity.Uid)
	assert.NoError(t, err)
	assert.True(t, exists)

	tx, err = p.StartTransaction(ctx)
	require.NoError(t, err)

	sig, err := p.LoadSignature(tx, testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.Signature, sig)

	err = tx.Commit()
	assert.NoError(t, err)

	priv, err := p.LoadPrivateKey(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.PrivateKey, priv)

	pub, err := p.LoadPublicKey(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.PublicKey, pub)

	ok, found, err := p.CheckAuth(context.Background(), testIdentity.Uid, testIdentity.AuthToken)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_LoadPrivateKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()

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
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()

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

func TestNewExtendedProtocol_BadSecret(t *testing.T) {
	badSecret := make([]byte, 31)
	rand.Read(badSecret)

	conf := &config.Config{
		SecretBytes32:      badSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	_, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.Error(t, err)
}

func TestExtendedProtocol_StoreSignature(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

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

	_, err = p.LoadSignature(tx, testIdentity.Uid)
	require.NoError(t, err)

	err = p.StoreSignature(tx, testIdentity.Uid, newSignature)
	require.NoError(t, err)

	tx2, err := p.StartTransaction(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx2)

	sig, err := p.LoadSignature(tx2, testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, newSignature, sig)
}

func TestExtendedProtocol_BadStoreSignature(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

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
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.Uid = uuid.Nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPrivateKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.PrivateKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPrivateKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	rand.Read(i.PrivateKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.PublicKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	rand.Read(i.PublicKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadSignature(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.Signature = make([]byte, p.SignatureLength()+1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadAuth(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.AuthToken = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	assert.Error(t, err)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), i.Uid, i.AuthToken)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	i := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_NotFound(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(context.Background(), uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(&MockCtxMngr{}, conf)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

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

	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	conf := &config.Config{
		SecretBytes32:      testSecret,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}

	p, err := NewExtendedProtocol(dm, conf)
	require.NoError(t, err)

	// generate identities
	var testIdentities []ent.Identity
	for i := 0; i < testLoad/10; i++ {
		testId := generateRandomIdentity()

		testIdentities = append(testIdentities, testId)
	}

	// store identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			err := storeIdentity(p, id, wg)
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

func protocolCheckAuth(auth, authToCheck string) error {
	pwHasher := &pw.Argon2idKeyDerivator{}

	ok, err := pwHasher.CheckPassword(context.Background(), authToCheck, auth)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("LoadAuthToken returned unexpected value")
	}
	return nil
}
