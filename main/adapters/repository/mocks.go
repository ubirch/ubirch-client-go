package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type extendedId struct {
	ent.Identity
	active bool
}

type MockCtxMngr struct {
	id    extendedId
	extId ent.ExternalIdentity
}

var _ ContextManager = (*MockCtxMngr)(nil)

func (m *MockCtxMngr) StartTransaction(ctx context.Context) (TransactionCtx, error) {
	return &MockTx{
		idBuf: extendedId{},
		id:    &m.id,
	}, nil
}

func (m *MockCtxMngr) StoreIdentity(t TransactionCtx, id ent.Identity) error {
	tx, ok := t.(*MockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}
	tx.idBuf = extendedId{Identity: id, active: true}

	return nil
}

func (m *MockCtxMngr) LoadIdentity(u uuid.UUID) (*ent.Identity, error) {
	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}
	id := m.id
	return &id.Identity, nil
}

func (m *MockCtxMngr) StoreActiveFlag(t TransactionCtx, u uuid.UUID, a bool) error {
	tx, ok := t.(*MockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.active = a
	return nil
}

func (m *MockCtxMngr) LoadActiveFlagForUpdate(t TransactionCtx, u uuid.UUID) (bool, error) {
	tx, ok := t.(*MockTx)
	if !ok {
		return false, fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return false, ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.active, nil
}

func (m *MockCtxMngr) LoadActiveFlag(u uuid.UUID) (bool, error) {
	return m.id.active, nil
}

func (m *MockCtxMngr) StoreSignature(t TransactionCtx, u uuid.UUID, s []byte) error {
	tx, ok := t.(*MockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.Signature = s
	return nil
}

func (m *MockCtxMngr) LoadSignatureForUpdate(t TransactionCtx, u uuid.UUID) ([]byte, error) {
	tx, ok := t.(*MockTx)
	if !ok {
		return nil, fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return nil, ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.Signature, nil
}

func (m *MockCtxMngr) StoreAuth(t TransactionCtx, u uuid.UUID, a string) error {
	tx, ok := t.(*MockTx)
	if !ok {
		return fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if tx.idBuf.Uid == uuid.Nil || tx.idBuf.Uid != u {
		return fmt.Errorf("tx invalid")
	}

	tx.idBuf.AuthToken = a
	return nil
}

func (m *MockCtxMngr) LoadAuthForUpdate(t TransactionCtx, u uuid.UUID) (string, error) {
	tx, ok := t.(*MockTx)
	if !ok {
		return "", fmt.Errorf("transactionCtx for MockCtxMngr is not of expected type *MockTx")
	}

	if m.id.Uid == uuid.Nil || m.id.Uid != u {
		return "", ErrNotExist
	}

	tx.idBuf = m.id

	return m.id.AuthToken, nil
}

func (m *MockCtxMngr) StoreExternalIdentity(ctx context.Context, externalId ent.ExternalIdentity) error {
	m.extId = externalId
	return nil
}

func (m *MockCtxMngr) LoadExternalIdentity(ctx context.Context, u uuid.UUID) (*ent.ExternalIdentity, error) {
	if m.extId.Uid == uuid.Nil || m.extId.Uid != u {
		return nil, ErrNotExist
	}
	return &m.extId, nil
}

func (m *MockCtxMngr) GetIdentityUUIDs() ([]uuid.UUID, error) {
	return []uuid.UUID{m.id.Uid}, nil
}

func (m *MockCtxMngr) GetExternalIdentityUUIDs() ([]uuid.UUID, error) {
	return []uuid.UUID{m.extId.Uid}, nil
}

func (m *MockCtxMngr) IsReady(ctx context.Context) error {
	return nil
}

func (m *MockCtxMngr) Close() error {
	return nil
}

type MockTx struct {
	idBuf extendedId
	id    *extendedId
}

var _ TransactionCtx = (*MockTx)(nil)

func (m *MockTx) Commit() error {
	*m.id = m.idBuf
	*m = MockTx{}
	return nil
}

func (m *MockTx) Rollback() error {
	*m = MockTx{}
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
