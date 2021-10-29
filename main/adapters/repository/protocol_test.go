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
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func TestProtocol(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
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

	_, err = p.LoadAuthToken(testIdentity.Uid)
	assert.Equal(t, ErrNotExist, err)

	// store identity
	tx, err = p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, testIdentity)
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

	auth, err := p.LoadAuthToken(testIdentity.Uid)
	assert.NoError(t, err)
	assert.Equal(t, testIdentity.AuthToken, auth)
}

func TestNewExtendedProtocol_BadSecret(t *testing.T) {
	badSecret := make([]byte, 31)
	rand.Read(badSecret)

	_, err := NewExtendedProtocol(&mockCtxMngr{}, badSecret)
	require.Error(t, err)
}

func TestExtendedProtocol_StoreSignature(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, testIdentity)
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

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, testIdentity)
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

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.Uid = uuid.Nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPrivateKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.PrivateKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPrivateKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	rand.Read(i.PrivateKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_NilPublicKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.PublicKey = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadPublicKey(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	rand.Read(i.PublicKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadSignature(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.Signature = make([]byte, p.SignatureLength()+1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func Test_StoreNewIdentity_BadAuth(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()
	i.AuthToken = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	assert.Error(t, err)
}

func TestExtendedProtocol_CheckAuth(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(i.Uid, i.AuthToken)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)
}

func TestExtendedProtocol_CheckAuth_Invalid(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	i := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, i)
	require.NoError(t, err)

	err = tx.Commit()
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(i.Uid, "invalid auth")
	require.NoError(t, err)
	assert.True(t, found)
	assert.False(t, ok)
}

func TestExtendedProtocol_CheckAuth_NotFound(t *testing.T) {
	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	ok, found, err := p.CheckAuth(uuid.New(), "auth")
	require.NoError(t, err)
	assert.False(t, found)
	assert.False(t, ok)
}

func TestProtocol_Cache(t *testing.T) {
	wg := &sync.WaitGroup{}

	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(&mockCtxMngr{}, testSecret)
	require.NoError(t, err)

	testIdentity := generateRandomIdentity()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	require.NoError(t, err)

	err = p.StoreNewIdentity(tx, testIdentity)
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

func TestProtocolLoad(t *testing.T) {
	wg := &sync.WaitGroup{}

	dm, err := initDB()
	require.NoError(t, err)
	defer cleanUpDB(t, dm)

	testSecret := make([]byte, 32)
	rand.Read(testSecret)

	p, err := NewExtendedProtocol(dm, testSecret)
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
		go func(identity ent.Identity) {
			err := storeIdentity(p, identity, wg)
			assert.NoError(t, err)
		}(testId)
	}
	wg.Wait()

	// check identities
	for _, testId := range testIdentities {
		wg.Add(1)
		go func(id ent.Identity) {
			err := checkIdentity(p, id, wg)
			assert.NoError(t, err)
		}(testId)
	}
	wg.Wait()
}

type mockTx struct {
	idBuf ent.Identity
	id    *ent.Identity
}

func (m *mockTx) Commit() error {
	*m.id = m.idBuf
	return nil
}

func (m mockTx) Rollback() error {
	m.idBuf = ent.Identity{}
	return nil
}

var _ TransactionCtx = (*mockTx)(nil)

type mockCtxMngr struct {
	id ent.Identity
}

var _ ContextManager = (*mockCtxMngr)(nil)

func (m *mockCtxMngr) StartTransaction(ctx context.Context) (TransactionCtx, error) {
	return &mockTx{
		idBuf: ent.Identity{},
		id:    &m.id,
	}, nil
}

func (m *mockCtxMngr) StoreNewIdentity(t TransactionCtx, id ent.Identity) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for mockCtxMngr is not of expected type *mockTx")
	}
	tx.idBuf = id
	return nil
}

func (m *mockCtxMngr) LoadSignature(t TransactionCtx, u uuid.UUID) ([]byte, error) {
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

func (m *mockCtxMngr) LoadPrivateKey(u uuid.UUID) ([]byte, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}
	return m.id.PrivateKey, nil
}

func (m *mockCtxMngr) LoadPublicKey(u uuid.UUID) ([]byte, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}
	return m.id.PublicKey, nil
}

func (m *mockCtxMngr) LoadAuthToken(u uuid.UUID) (string, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return "", ErrNotExist
	}
	return m.id.AuthToken, nil
}

func (m *mockCtxMngr) IsReady() error {
	return nil
}

func (m *mockCtxMngr) Close() error {
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
