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
	ContextManager
	keyEncrypter *encrypters.KeyEncrypter
	keyCache     *KeyCache
	authCache    *sync.Map // {<uuid>: <auth token>}
}

func NewExtendedProtocol(ctxManager ContextManager, secret []byte, client *clients.Client) (*ExtendedProtocol, error) {
	keyCache := NewKeyCache()

	crypto := &ubirch.ECDSACryptoContext{
		Keystore: keyCache,
	}

	enc, err := encrypters.NewKeyEncrypter(secret, crypto)
	if err != nil {
		return nil, err
	}

	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: crypto,
		},
		Client:         client,
		ContextManager: ctxManager,
		keyEncrypter:   enc,
		keyCache:       keyCache,
		authCache:      &sync.Map{},
	}

	return p, nil
}

func (p *ExtendedProtocol) StoreNewIdentity(tx TransactionCtx, i ent.Identity) error {
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

	return p.ContextManager.StoreNewIdentity(tx, i)
}

// StoreSignature stores the signature and commits the transaction
func (p *ExtendedProtocol) StoreSignature(tx TransactionCtx, uid uuid.UUID, signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}

	err := p.ContextManager.StoreSignature(tx, uid, signature)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (p *ExtendedProtocol) LoadPrivateKey(uid uuid.UUID) (privKeyPEM []byte, err error) {
	privKeyPEM, err = p.keyCache.GetPrivateKey(uid)
	if err != nil {
		encryptedPriv, err := p.ContextManager.LoadPrivateKey(uid)
		if err != nil {
			return nil, err
		}

		privKeyPEM, err = p.keyEncrypter.Decrypt(encryptedPriv)
		if err != nil {
			return nil, err
		}

		err = p.keyCache.SetPrivateKey(uid, privKeyPEM)
		if err != nil {
			return nil, err
		}
	}

	return privKeyPEM, nil
}

func (p *ExtendedProtocol) LoadPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	pubKeyPEM, err = p.keyCache.GetPublicKey(uid)
	if err != nil {
		pubKeyPEM, err = p.ContextManager.LoadPublicKey(uid)
		if err != nil {
			return nil, err
		}

		err = p.keyCache.SetPublicKey(uid, pubKeyPEM)
		if err != nil {
			return nil, err
		}
	}

	return pubKeyPEM, nil
}

func (p *ExtendedProtocol) LoadAuthToken(uid uuid.UUID) (auth string, err error) {
	_auth, found := p.authCache.Load(uid)

	if found {
		auth, found = _auth.(string)
	}

	if !found {
		auth, err = p.ContextManager.LoadAuthToken(uid)
		if err != nil {
			return "", err
		}

		if len(auth) == 0 {
			return "", fmt.Errorf("%s: empty auth token", uid)
		}

		p.authCache.Store(uid, auth)
	}

	return auth, nil
}

func (p *ExtendedProtocol) IsInitialized(uid uuid.UUID) (initialized bool, err error) {
	_, err = p.LoadAuthToken(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *ExtendedProtocol) CheckAuth(uid uuid.UUID, authToCheck string) (ok bool, found bool, err error) {
	actualAuth, err := p.LoadAuthToken(uid)
	if err == ErrNotExist {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	return actualAuth == authToCheck, true, nil
}

func (p *ExtendedProtocol) checkIdentityAttributes(i ent.Identity) error {
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
