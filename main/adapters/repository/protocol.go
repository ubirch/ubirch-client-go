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
}

// Ensure ExtendedProtocol implements the ContextManager interface
var _ ContextManager = (*ExtendedProtocol)(nil)

func NewExtendedProtocol(ctxManager ContextManager, secret []byte, client *clients.Client) (*ExtendedProtocol, error) {
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
		ContextManager: ctxManager,
		keyEncrypter:   enc,
	}

	return p, nil
}

func (p *ExtendedProtocol) StoreNewIdentity(tx interface{}, i *ent.Identity) error {
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

	return p.ContextManager.StoreNewIdentity(tx, i)
}

func (p *ExtendedProtocol) GetIdentityWithLock(ctx context.Context, uid uuid.UUID) (interface{}, *ent.Identity, error) {
	tx, i, err := p.ContextManager.GetIdentityWithLock(ctx, uid)
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
func (p *ExtendedProtocol) SetSignature(tx interface{}, uid uuid.UUID, signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}

	err := p.ContextManager.SetSignature(tx, uid, signature)
	if err != nil {
		return err
	}

	return p.CommitTransaction(tx)
}

func (p *ExtendedProtocol) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	encryptedPrivateKey, err := p.ContextManager.GetPrivateKey(uid)
	if err != nil {
		return nil, err
	}

	return p.keyEncrypter.Decrypt(encryptedPrivateKey)
}

func (p *ExtendedProtocol) GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	publicKeyBytes, err := p.ContextManager.GetPublicKey(uid)
	if err != nil {
		return nil, err
	}

	return p.PublicKeyBytesToPEM(publicKeyBytes)
}

func (p *ExtendedProtocol) GetAuthToken(uid uuid.UUID) (string, error) {
	authToken, err := p.ContextManager.GetAuthToken(uid)
	if err != nil {
		return "", err
	}

	if len(authToken) == 0 {
		return "", fmt.Errorf("%s: empty auth token", uid)
	}

	return authToken, nil
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
