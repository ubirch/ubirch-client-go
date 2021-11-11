package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type MockCtxMngr struct {
	id     ent.Identity
	active bool
}

var _ ContextManager = (*MockCtxMngr)(nil)

func (m *MockCtxMngr) StartTransaction(ctx context.Context) (TransactionCtx, error) {
	return &mockTx{
		idBuf: ent.Identity{},
		id:    &m.id,
	}, nil
}

func (m *MockCtxMngr) StoreIdentity(t TransactionCtx, id ent.Identity) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}
	tx.idBuf = id
	return nil
}

func (m *MockCtxMngr) LoadIdentity(u uuid.UUID) (*ent.Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}
	id := m.id
	return &id, nil
}

func (m *MockCtxMngr) StoreActiveFlag(t TransactionCtx, u uuid.UUID, a bool) error {
	m.active = a
	return nil
}

func (m *MockCtxMngr) LoadActiveFlagForUpdate(t TransactionCtx, u uuid.UUID) (bool, error) {
	return m.active, nil
}

func (m *MockCtxMngr) LoadActiveFlag(u uuid.UUID) (bool, error) {
	return m.active, nil
}

func (m *MockCtxMngr) StoreSignature(t TransactionCtx, u uuid.UUID, s []byte) error {
	tx, ok := t.(*mockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.Signature = s
	return nil
}

func (m *MockCtxMngr) LoadSignatureForUpdate(t TransactionCtx, u uuid.UUID) ([]byte, error) {
	tx, ok := t.(*mockTx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *mockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.Signature, nil
}

func (m *MockCtxMngr) IsReady() error {
	return nil
}

func (m *MockCtxMngr) Close() error {
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
