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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/encryption"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	pw "github.com/ubirch/ubirch-client-go/main/adapters/password-hashing"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
	keyEncrypter *encryption.KeyEncrypter
	keyCache     *KeyCache

	pwHasher  *pw.Argon2idKeyDerivator
	authCache *sync.Map // {<uuid>: <auth token>}
}

func NewExtendedProtocol(ctxManager ContextManager, conf *config.Config) (*ExtendedProtocol, error) {
	keyCache := NewKeyCache()

	crypto := &ubirch.ECDSACryptoContext{
		Keystore: keyCache,
	}

	enc, err := encryption.NewKeyEncrypter(conf.SecretBytes32, crypto)
	if err != nil {
		return nil, err
	}

	argon2idParams := pw.GetArgon2idParams(conf.KdParamMemMiB, conf.KdParamTime, conf.KdParamParallelism,
		conf.KdParamKeyLen, conf.KdParamSaltLen)
	params, _ := json.Marshal(argon2idParams)
	log.Debugf("initialize argon2id key derivation with parameters %s", params)
	log.Debugf("max. total memory to use for key derivation at a time: %d MiB", conf.KdMaxTotalMemMiB)
	if conf.KdUpdateParams {
		log.Debugf("key derivation parameter update for already existing password hashes enabled")
	}

	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: crypto,
		},
		ContextManager: ctxManager,
		keyEncrypter:   enc,
		keyCache:       keyCache,

		pwHasher:  pw.NewArgon2idKeyDerivator(conf.KdMaxTotalMemMiB, argon2idParams, conf.KdUpdateParams),
		authCache: &sync.Map{},
	}

	return p, nil
}

func (p *ExtendedProtocol) StoreIdentity(tx TransactionCtx, i ent.Identity) error {
	// check validity of identity attributes
	err := p.checkIdentityAttributes(&i)
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

	// hash auth token
	i.AuthToken, err = p.pwHasher.GeneratePasswordHash(context.Background(), i.AuthToken)
	if err != nil {
		return fmt.Errorf("generating password hash failed: %v", err)
	}

	return p.ContextManager.StoreIdentity(tx, i)
}

func (p *ExtendedProtocol) LoadIdentity(uid uuid.UUID) (*ent.Identity, error) {
	i, err := p.ContextManager.LoadIdentity(uid)
	if err != nil {
		return nil, err
	}

	// check validity of identity attributes
	err = p.checkIdentityAttributes(i)
	if err != nil {
		return nil, err
	}

	// load caches
	i.PrivateKey, err = p.keyEncrypter.Decrypt(i.PrivateKey)
	if err != nil {
		return nil, err
	}

	err = p.keyCache.SetPrivateKey(uid, i.PrivateKey)
	if err != nil {
		return nil, err
	}

	i.PublicKey, err = p.PublicKeyBytesToPEM(i.PublicKey)
	if err != nil {
		return nil, err
	}

	err = p.keyCache.SetPublicKey(uid, i.PublicKey)
	if err != nil {
		return nil, err
	}

	p.authCache.Store(uid, i.AuthToken)

	return i, nil
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
		i, err := p.LoadIdentity(uid)
		if err != nil {
			return nil, err
		}

		privKeyPEM = i.PrivateKey
	}

	return privKeyPEM, nil
}

func (p *ExtendedProtocol) LoadPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	pubKeyPEM, err = p.keyCache.GetPublicKey(uid)
	if err != nil {
		i, err := p.LoadIdentity(uid)
		if err != nil {
			return nil, err
		}

		pubKeyPEM = i.PublicKey
	}

	return pubKeyPEM, nil
}

func (p *ExtendedProtocol) LoadAuth(uid uuid.UUID) (auth string, err error) {
	_auth, found := p.authCache.Load(uid)

	if found {
		auth, found = _auth.(string)
	}

	if !found {
		i, err := p.LoadIdentity(uid)
		if err != nil {
			return "", err
		}

		auth = i.AuthToken
	}

	return auth, nil
}

func (p *ExtendedProtocol) IsInitialized(uid uuid.UUID) (initialized bool, err error) {
	_, err = p.LoadAuth(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *ExtendedProtocol) CheckAuth(ctx context.Context, uid uuid.UUID, authToCheck string) (ok, found bool, err error) {
	pwHah, err := p.LoadAuth(uid)
	if err == ErrNotExist {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	found = true

	needsUpdate, ok, err := p.pwHasher.CheckPassword(ctx, pwHah, authToCheck)
	if err != nil || !ok {
		return ok, found, err
	}

	if needsUpdate {
		if err := p.updatePwHash(uid, authToCheck); err != nil {
			log.Errorf("%s: password hash update failed: %v", uid, err)
		}
	}

	return ok, found, err
}

func (p *ExtendedProtocol) updatePwHash(uid uuid.UUID, authToCheck string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("could not initialize transaction: %v", err)
	}

	_, err = p.ContextManager.LoadAuthForUpdate(tx, uid)
	if err != nil {
		return fmt.Errorf("could not aquire lock for update: %v", err)
	}

	updatedHash, err := p.pwHasher.GeneratePasswordHash(ctx, authToCheck)
	if err != nil {
		return fmt.Errorf("could not generate new password hash: %v", err)
	}

	err = p.ContextManager.StoreAuth(tx, uid, updatedHash)
	if err != nil {
		return fmt.Errorf("could not store updated password hash: %v", err)
	}

	p.authCache.Store(uid, updatedHash)

	return nil
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
