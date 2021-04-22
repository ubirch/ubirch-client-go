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

package todo

import (
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	Protocol            *ExtendedProtocol
	Client              *Client
	SubjectCountry      string
	SubjectOrganization string
}

func (i *IdentityHandler) InitIdentities(identities map[string]string) error {
	// create and register keys for identities
	log.Infof("initializing %d identities...", len(identities))
	for name, auth := range identities {
		// make sure identity name is a valid UUID
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
		}

		// make sure that all auth tokens from config are being set (this is here for backwards compatibility)
		if _, ok := i.Protocol.ContextManager.(*FileManager); ok {
			err = i.Protocol.SetAuthToken(uid, auth)
			if err != nil {
				return err
			}
		}

		err = i.initIdentity(uid, auth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) initIdentity(uid uuid.UUID, auth string) error {
	// make sure identity has an auth token
	if len(auth) == 0 {
		return fmt.Errorf("%s: auth token has zero length", uid)
	}

	err := i.Protocol.StartTransaction(uid)
	if err != nil {
		return err
	}

	err = i.setIdentityAttributes(uid, auth)
	if err != nil {
		ctxErr := i.Protocol.EndTransaction(uid, false)
		if ctxErr != nil {
			log.Error(err)
			log.Fatalf("can not reset context: %v", ctxErr) // todo dont panic ?
		}
		return err
	}

	ctxErr := i.Protocol.EndTransaction(uid, true)
	if ctxErr != nil {
		log.Fatalf("can not end transaction: %v", ctxErr) // todo dont panic ?
	}

	return nil
}

func (i *IdentityHandler) setIdentityAttributes(uid uuid.UUID, auth string) error {
	// check if identity is already initialized
	if i.Protocol.PrivateKeyExists(uid) {
		return nil
	}

	err := i.Protocol.SetAuthToken(uid, auth)
	if err != nil {
		return err
	}

	genesisSignature := make([]byte, i.Protocol.SignatureLength())
	err = i.Protocol.SetSignature(uid, genesisSignature)
	if err != nil {
		return err
	}

	err = i.initKey(uid, auth)
	if err != nil {
		return err
	}

	return nil
}

func (i *IdentityHandler) initKey(uid uuid.UUID, auth string) error {
	// generate new key pair
	log.Printf("generating new key pair for UUID %s", uid)
	err := i.Protocol.GenerateKey(uid)
	if err != nil {
		return fmt.Errorf("generating new key pair for UUID %s failed: %v", uid, err)
	}

	// register public key at the ubirch backend
	return i.registerPublicKey(uid, auth)
}

func (i *IdentityHandler) registerPublicKey(uid uuid.UUID, auth string) error {
	pubKey, err := i.Protocol.Crypto.GetPublicKey(uid)
	if err != nil {
		return err
	}
	log.Debugf("%s: public key: %x", uid, pubKey)

	cert, err := i.Protocol.GetSignedKeyRegistration(uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, cert)

	err = i.Client.submitKeyRegistration(uid, cert, auth)
	if err != nil {
		return fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.sendCSROrLogError(uid)

	return nil
}
func (i *IdentityHandler) sendCSROrLogError(uid uuid.UUID) {
	err := i.sendCSR(uid)
	if err != nil {
		log.Error(err)
	}
}

func (i *IdentityHandler) sendCSR(uid uuid.UUID) error {
	// submit a X.509 Certificate Signing Request for the public key
	csr, err := i.Protocol.GetCSR(uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.Client.submitCSR(uid, csr)
	if err != nil {
		return fmt.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}
