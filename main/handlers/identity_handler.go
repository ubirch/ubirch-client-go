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
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	Protocol            *ExtendedProtocol
	SubjectCountry      string
	SubjectOrganization string
}

func (i *IdentityHandler) InitIdentities(identities map[string]string) error {
	// create and register keys for identities
	log.Debugf("initializing %d identities...", len(identities))
	for name, auth := range identities {
		// make sure identity name is a valid UUID
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
		}

		// check if identity is already initialized
		exists, err := i.Protocol.Exists(uid)
		if err != nil {
			return fmt.Errorf("can not check existing context for %s: %s", name, err)
		}

		if exists {
			// already initialized
			log.Debugf("%s already initialized (skip)", uid)
			continue
		}

		// make sure identity has an auth token
		if len(auth) == 0 {
			return fmt.Errorf("missing auth token for identity %s", name)
		}

		err = i.InitIdentity(uid, auth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID, auth string) error {
	log.Infof("initializing new identity %s", uid)

	// generate a new private key
	privKeyPEM, err := i.Protocol.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating new key for UUID %s failed: %v", uid, err)
	}

	pubKeyPEM, err := i.Protocol.GetPublicKeyFromPrivateKey(privKeyPEM)
	if err != nil {
		return err
	}

	newIdentity := &ent.Identity{
		Uid:        uid.String(),
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		Signature:  make([]byte, i.Protocol.SignatureLength()),
		AuthToken:  auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return err
	}

	err = i.Protocol.StoreNewIdentity(tx, newIdentity)
	if err != nil {
		return err
	}

	// register public key at the ubirch backend
	err = i.registerPublicKey(privKeyPEM, uid, auth)
	if err != nil {
		return err
	}

	return i.Protocol.CloseTransaction(tx, commit)
}

func (i *IdentityHandler) FetchIdentity(uid uuid.UUID) (*ent.Identity, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return nil, err
	}

	return i.Protocol.FetchIdentity(tx, uid)
}

func (i *IdentityHandler) registerPublicKey(privKeyPEM []byte, uid uuid.UUID, auth string) error {
	cert, err := i.Protocol.GetSignedKeyRegistration(privKeyPEM, uid)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, cert)

	err = i.Protocol.SubmitKeyRegistration(uid, cert, auth)
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

	err = i.Protocol.SubmitCSR(uid, csr)
	if err != nil {
		return fmt.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}
