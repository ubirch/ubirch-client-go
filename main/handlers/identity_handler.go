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

package handlers

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

//func (i *IdentityHandler) InitIdentities(identities map[string]string) error {
//	// create and register keys for identities
//	log.Infof("initializing %d identities...", len(identities))
//	for name, auth := range identities {
//		// make sure identity name is a valid UUID
//		uid, err := uuid.Parse(name)
//		if err != nil {
//			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
//		}
//
//		// make sure that all auth tokens from config are being set (this is here for backwards compatibility)
//		if _, ok := i.Protocol.ContextManager.(*FileManager); ok {
//			err = i.Protocol.SetAuthToken(uid, auth)
//			if err != nil {
//				return err
//			}
//		}
//
//		err = i.setIdentityAttributes(uid, auth)
//		if err != nil {
//			return err
//		}
//	}
//
//	return nil
//}

//func (i *IdentityHandler) setIdentityAttributes(uid uuid.UUID, auth string) error {
//	if len(auth) == 0 {
//		return fmt.Errorf("%s: auth token has zero length", uid)
//	}
//	// check if identity is already initialized
//	exists, err := i.Protocol.Exists(uid)
//	if err != nil {
//		log.Fatal(err)
//	}
//	if exists {
//		return nil
//	}
//
//	log.Infof("%s: initializing new identity", uid)
//
//	// set auth token
//	err = i.Protocol.SetAuthToken(uid, auth)
//	if err != nil {
//		return err
//	}
//
//	// set signature
//	genesisSignature := make([]byte, i.Protocol.SignatureLength())
//	err = i.Protocol.SetSignature(uid, genesisSignature)
//	if err != nil {
//		return err
//	}
//
//	// generate a new private key
//	log.Debugf("%s: generating new key pair", uid)
//	privKeyPEM, err := i.Protocol.GenerateKey()
//	if err != nil {
//		return fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
//	}
//
//	// set private key
//	err = i.Protocol.SetPrivateKey(uid, privKeyPEM)
//	if err != nil {
//		return err
//	}
//
//
//
//	err = i.Protocol.SetPublicKey(uid, pubKeyPEM)
//	if err != nil {
//		return err
//	}
//
//	// register public key at the ubirch backend
//	return i.RegisterPublicKey(privKeyPEM, uid, auth)
//}

func (i *IdentityHandler) RegisterPublicKey(privKeyPEM []byte, uid uuid.UUID, auth string) error {
	cert, err := i.Protocol.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, cert)

	err = i.Client.SubmitKeyRegistration(uid, cert, auth)
	if err != nil {
		return fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.sendCSROrLogError(privKeyPEM, uid)

	return nil
}

func (i *IdentityHandler) sendCSROrLogError(privKeyPEM []byte, uid uuid.UUID) {
	err := i.sendCSR(privKeyPEM, uid)
	if err != nil {
		log.Error(err)
	}
}

// sendCSR  generates and submits a signed a X.509 Certificate Signing Request for the public key
func (i *IdentityHandler) sendCSR(privKeyPEM []byte, uid uuid.UUID) error {
	csr, err := i.Protocol.GetCSR(privKeyPEM, uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.Client.SubmitCSR(uid, csr)
	if err != nil {
		return fmt.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}
