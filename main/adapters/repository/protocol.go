// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repository

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/encrypters"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	*clients.Client
	StorageManager
	keyEncrypter *encrypters.KeyEncrypter

	privateKeyCache *sync.Map // {<uuid>: <private key>}
	publicKeyCache  *sync.Map // {<uuid>: <public key>}
	authTokenCache  *sync.Map // {<uuid>: <auth token>}
}

// Ensure ExtendedProtocol implements the StorageManager interface
var _ StorageManager = (*ExtendedProtocol)(nil)

func NewExtendedProtocol(storageManager StorageManager, secret []byte, client *clients.Client) (*ExtendedProtocol, error) {
	crypto := &ubirch.ECDSACryptoContext{}

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: crypto,
		},
		Client:         client,
		StorageManager: storageManager,
		keyEncrypter:   enc,

		privateKeyCache: &sync.Map{},
		publicKeyCache:  &sync.Map{},
		authTokenCache:  &sync.Map{},
	}

	return p, nil
}

func (p *ExtendedProtocol) StoreNewIdentity(tx TransactionCtx, i *ent.Identity) error {
	// check validity of identity attributes
	err := p.checkIdentityAttributes(i)
	if err != nil {
		return err
	}

	// encrypt private key
	i.PrivateKey, err = p.keyEncrypter.Encrypt(i.PrivateKey)
	if err != nil {
		return err
	}

	// store public key raw bytes
	i.PublicKey, err = p.PublicKeyPEMToBytes(i.PublicKey)
	if err != nil {
		return err
	}

	return p.StorageManager.StoreNewIdentity(tx, i)
}

func (p *ExtendedProtocol) GetIdentityWithLock(ctx context.Context, uid uuid.UUID) (TransactionCtx, *ent.Identity, error) {
	tx, i, err := p.StorageManager.GetIdentityWithLock(ctx, uid)
	if err != nil {
		return nil, nil, err
	}

	// decrypt private key
	i.PrivateKey, err = p.keyEncrypter.Decrypt(i.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// return public key in PEM format
	i.PublicKey, err = p.PublicKeyBytesToPEM(i.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return tx, i, nil
}

// SetSignature stores the signature and commits the transaction
func (p *ExtendedProtocol) SetSignature(tx TransactionCtx, uid uuid.UUID, signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}

	err := p.StorageManager.SetSignature(tx, uid, signature)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (p *ExtendedProtocol) GetPrivateKey(uid uuid.UUID) (privKeyPEM []byte, err error) {
	_priv, found := p.privateKeyCache.Load(uid)

	if found {
		privKeyPEM, found = _priv.([]byte)
	}

	if !found {
		encryptedPriv, err := p.StorageManager.GetPrivateKey(uid)
		if err != nil {
			return nil, err
		}

		privKeyPEM, err = p.keyEncrypter.Decrypt(encryptedPriv)
		if err != nil {
			return nil, err
		}

		p.privateKeyCache.Store(uid, privKeyPEM)
	}

	return privKeyPEM, nil
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	_pub, found := p.publicKeyCache.Load(uid)

	if found {
		pubKeyPEM, found = _pub.([]byte)
	}

	if !found {
		publicKeyBytes, err := p.StorageManager.GetPublicKey(uid)
		if err != nil {
			return nil, err
		}

		pubKeyPEM, err = p.PublicKeyBytesToPEM(publicKeyBytes)
		if err != nil {
			return nil, err
		}

		p.publicKeyCache.Store(uid, pubKeyPEM)
	}

	return pubKeyPEM, nil
}

func (p *ExtendedProtocol) GetAuthToken(uid uuid.UUID) (auth string, err error) {
	_auth, found := p.authTokenCache.Load(uid)

	if found {
		auth, found = _auth.(string)
	}

	if !found {
		auth, err = p.StorageManager.GetAuthToken(uid)
		if err != nil {
			return "", err
		}

		if len(auth) == 0 {
			return "", fmt.Errorf("%s: empty auth token", uid)
		}

		p.authTokenCache.Store(uid, auth)
	}

	return auth, nil
}

func (p *ExtendedProtocol) IsInitialized(uid uuid.UUID) (initialized bool, err error) {
	_, err = p.GetAuthToken(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *ExtendedProtocol) CheckAuth(uid uuid.UUID, authToCheck string) (ok bool, found bool, err error) {
	actualAuth, err := p.GetAuthToken(uid)
	if err == ErrNotExist {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	return actualAuth == authToCheck, true, nil
}

func (p *ExtendedProtocol) checkIdentityAttributes(i *ent.Identity) error {
	if i.Uid == uuid.Nil {
		return fmt.Errorf("uuid has Nil value: %s", i.Uid)
	}

	if len(i.PrivateKey) == 0 {
		return fmt.Errorf("private key is empty")
	}

	if len(i.PublicKey) == 0 {
		return fmt.Errorf("public key is empty")
	}

	if len(i.Signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(i.Signature))
	}

	if len(i.AuthToken) == 0 {
		return fmt.Errorf("%s: empty auth token", i.Uid)
	}

	return nil
}
