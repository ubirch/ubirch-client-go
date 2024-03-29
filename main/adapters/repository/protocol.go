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
	"bytes"
	"context"
	"encoding/base64"
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

var (
	signedUPPHeader  = []byte{0x95, 0x22}
	chainedUPPHeader = []byte{0x96, 0x23}
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
	keyEncrypter *encryption.KeyEncrypter
	keyCache     *KeyCache

	pwHasher  *pw.Argon2idKeyDerivator
	authCache *sync.Map // {<uuid>: <auth token>}

	verifyNiomonResponse bool
	backendUUID          uuid.UUID
}

func NewExtendedProtocol(ctxManager ContextManager, conf *config.Config) (*ExtendedProtocol, error) {
	err := logKnownIdentities(ctxManager, conf.LogKnownIdentities)
	if err != nil {
		return nil, err
	}

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
	if conf.KdMaxTotalMemMiB != 0 {
		log.Debugf("max. total memory to use for key derivation at a time: %d MiB", conf.KdMaxTotalMemMiB)
	}
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

	if conf.VerifyNiomonResponse {
		if conf.NiomonIdentity == nil {
			return nil, fmt.Errorf("config field NiomonIdentity is nil pointer")
		}
		err = p.setBackendVerificationKey(conf.NiomonIdentity.UUID, conf.NiomonIdentity.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *ExtendedProtocol) setBackendVerificationKey(id uuid.UUID, pubKeyBytes []byte) error {
	pubKeyPEM, err := p.PublicKeyBytesToPEM(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid backend response verification key [bytes]: %v", err)
	}

	if err = p.keyCache.SetPublicKey(id, pubKeyPEM); err != nil {
		return fmt.Errorf("couldn't set backend response verification key in key cache: %v", err)
	}

	p.verifyNiomonResponse = true
	p.backendUUID = id

	return nil
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

func (p *ExtendedProtocol) ClearKeysFromCache(uid uuid.UUID) {
	p.keyCache.ClearKeypair(uid)
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

func (p *ExtendedProtocol) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) (err error) {
	// store public key raw bytes
	extId.PublicKey, err = p.PublicKeyPEMToBytes(extId.PublicKey)
	if err != nil {
		return err
	}

	return p.ContextManager.StoreExternalIdentity(ctx, extId)
}

func (p *ExtendedProtocol) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (*ent.ExternalIdentity, error) {
	extId, err := p.ContextManager.LoadExternalIdentity(ctx, uid)
	if err != nil {
		return nil, err
	}

	extId.PublicKey, err = p.PublicKeyBytesToPEM(extId.PublicKey)
	if err != nil {
		return nil, err
	}

	// load public key to cache
	err = p.keyCache.SetPublicKey(uid, extId.PublicKey)
	if err != nil {
		return nil, err
	}

	return extId, nil
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
			if err == ErrNotExist { // if the public key is not one of the internal identities, try external identities
				return p.loadPublicKeyFromExternalIdentity(uid)
			} else {
				return nil, err
			}
		}

		return i.PublicKey, nil
	}

	return pubKeyPEM, nil
}

func (p *ExtendedProtocol) loadPublicKeyFromExternalIdentity(uid uuid.UUID) (pubKeyPEM []byte, err error) {
	extId, err := p.LoadExternalIdentity(context.TODO(), uid)
	if err != nil {
		return nil, err
	}
	return extId.PublicKey, nil
}

func (p *ExtendedProtocol) IsInitialized(uid uuid.UUID) (initialized bool, err error) {
	_, err = p.LoadPrivateKey(uid)
	if err == ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (p *ExtendedProtocol) VerifyBackendResponse(requestUPP, responseUPP []byte) (signatureOk bool, chainOk bool, err error) {
	if !p.verifyNiomonResponse {
		return false, false, nil
	}

	if len(responseUPP) == 0 {
		return signatureOk, chainOk, fmt.Errorf("response from UBIRCH Trust Service is empty")
	}

	// check if backend response is a UPP or something else, like an error message string, for example "Timeout"
	if !hasUPPHeaders(responseUPP) {
		return signatureOk, chainOk, fmt.Errorf("response from UBIRCH Trust Service is not a UPP: %q", responseUPP)
	}

	signatureOk, err = p.verifyBackendResponseSignature(responseUPP)
	if err != nil {
		return signatureOk, chainOk, err
	}

	chainOk, err = p.verifyBackendResponseChain(requestUPP, responseUPP)
	return signatureOk, chainOk, err
}

// hasUPPHeaders is a helper function to check if the data starts with the expected UPP headers
func hasUPPHeaders(data []byte) bool {
	return bytes.HasPrefix(data, signedUPPHeader) || bytes.HasPrefix(data, chainedUPPHeader)
}

// verifyBackendResponseSignature verifies the signature of the backend response UPP
func (p *ExtendedProtocol) verifyBackendResponseSignature(upp []byte) (bool, error) {
	if verified, err := p.Verify(p.backendUUID, upp); !verified {
		if err != nil {
			return false, fmt.Errorf("could not verify backend response signature: %v", err)
		}
		pub, _ := p.Crypto.GetPublicKeyBytes(p.backendUUID)
		return false, fmt.Errorf("backend response signature verification failed with public key: %s",
			base64.StdEncoding.EncodeToString(pub))
	}
	return true, nil
}

// verifyBackendResponseChain verifies that backend response previous signature matches signature of request UPP
func (p *ExtendedProtocol) verifyBackendResponseChain(requestUPPBytes, responseUPPBytes []byte) (bool, error) {
	requestUPP, err := ubirch.Decode(requestUPPBytes)
	if err != nil {
		return false, fmt.Errorf("decoding request UPP failed: %v: %x", err, requestUPPBytes)
	}

	responseUPP, err := ubirch.Decode(responseUPPBytes)
	if err != nil {
		return false, fmt.Errorf("decoding response UPP failed: %v: %x", err, responseUPPBytes)
	}

	if responseUPP.GetVersion() != ubirch.Chained {
		log.Warnf("backend response UPP is not chained! request UPP: %x, response UPP: %x",
			requestUPPBytes, responseUPPBytes)
		return false, nil
	}

	if chainOK, err := ubirch.CheckChainLink(requestUPP, responseUPP); !chainOK {
		if err != nil {
			return false, fmt.Errorf("could not verify backend response chain: %v", err)
		}
		return false, fmt.Errorf("backend response chain check failed")
	}

	return true, nil
}

func (p *ExtendedProtocol) CheckAuth(ctx context.Context, uid uuid.UUID, authToCheck string) (ok, found bool, err error) {
	_auth, found := p.authCache.Load(uid)

	if found {
		if auth, ok := _auth.(string); ok {
			return auth == authToCheck, found, err
		}
	}

	i, err := p.LoadIdentity(uid)
	if err == ErrNotExist {
		return ok, found, nil
	}
	if err != nil {
		return ok, found, err
	}

	found = true

	needsUpdate, ok, err := p.pwHasher.CheckPassword(ctx, i.AuthToken, authToCheck)
	if err != nil || !ok {
		return ok, found, err
	}

	// auth check was successful
	p.authCache.Store(uid, authToCheck)

	if needsUpdate {
		if err := p.updatePwHash(uid, authToCheck); err != nil {
			log.Errorf("%s: password hash update failed: %v", uid, err)
		}
	}

	return ok, found, err
}

func (p *ExtendedProtocol) updatePwHash(uid uuid.UUID, authToCheck string) error {
	log.Infof("%s: updating password hash", uid)

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

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("could not commit transaction after storing updated password hash: %v", err)
	}

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
		return fmt.Errorf("empty auth token")
	}

	return nil
}

func logKnownIdentities(ctxManager ContextManager, logKnownIdentities bool) error {
	ids, err := ctxManager.GetIdentityUUIDs()
	if err != nil {
		return err
	}

	log.Infof("%d known internal identities (signing and verification)", len(ids))
	if logKnownIdentities {
		for i, id := range ids {
			log.Infof("%6d: %s", i, id)
		}
	}

	extIds, err := ctxManager.GetExternalIdentityUUIDs()
	if err != nil {
		return err
	}

	log.Infof("%d known external identities (verification only)", len(extIds))
	if logKnownIdentities {
		for i, id := range extIds {
			log.Infof("%6d: %s", i, id)
		}
	}

	return nil
}
