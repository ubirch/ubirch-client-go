package repository

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var (
	ErrNotFound = errors.New("key not found in cache")
)

type KeyCache struct {
	privateKeyCache *sync.Map // {<uuid>: <private key [PEM]>}
	publicKeyCache  *sync.Map // {<uuid>: <public key [PEM]>}
}

// Ensure KeyCache implements the Keystorer interface
var _ ubirch.Keystorer = (*KeyCache)(nil)

func NewKeyCache() *KeyCache {
	return &KeyCache{
		privateKeyCache: &sync.Map{},
		publicKeyCache:  &sync.Map{},
	}
}

func (k *KeyCache) GetIDs() ([]uuid.UUID, error) {
	panic("implement me")
}

func (k *KeyCache) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	_priv, found := k.privateKeyCache.Load(id)

	if !found {
		return nil, ErrNotFound
	}

	return _priv.([]byte), nil
}

func (k *KeyCache) SetPrivateKey(id uuid.UUID, key []byte) error {
	k.privateKeyCache.Store(id, key)
	return nil
}

func (k *KeyCache) PrivateKeyExists(id uuid.UUID) (bool, error) {
	_, found := k.privateKeyCache.Load(id)
	return found, nil
}

func (k *KeyCache) GetPublicKey(id uuid.UUID) ([]byte, error) {
	_pub, found := k.publicKeyCache.Load(id)

	if !found {
		return nil, ErrNotFound
	}

	return _pub.([]byte), nil
}

func (k *KeyCache) SetPublicKey(id uuid.UUID, key []byte) error {
	k.publicKeyCache.Store(id, key)
	return nil
}

func (k *KeyCache) PublicKeyExists(id uuid.UUID) (bool, error) {
	_, found := k.publicKeyCache.Load(id)
	return found, nil
}

func (k *KeyCache) ClearKeypair(id uuid.UUID) {
	k.publicKeyCache.Delete(id)
	k.privateKeyCache.Delete(id)
}
