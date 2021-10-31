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
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

type IdentityHandler struct {
	Protocol              *repository.ExtendedProtocol
	SubmitKeyRegistration func(uid uuid.UUID, auth string, cert []byte) error
	SubmitCSR             func(uid uuid.UUID, csr []byte) error
	SubjectCountry        string
	SubjectOrganization   string
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

		// make sure identity has an auth token
		if len(auth) == 0 {
			return fmt.Errorf("missing auth token for identity %s", name)
		}

		_, err = i.InitIdentity(uid, auth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) InitIdentity(uid uuid.UUID, auth string) (csrPEM []byte, err error) {
	log.Infof("%s: initializing identity", uid)

	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if initialized {
		return nil, h.ErrAlreadyInitialized
	}

	// generate a new private key
	err = i.Protocol.GenerateKey(uid)
	if err != nil {
		return nil, err
	}

	privKeyPEM, err := i.Protocol.LoadPrivateKey(uid)
	if err != nil {
		return nil, err
	}

	pubKeyPEM, err := i.Protocol.LoadPublicKey(uid)
	if err != nil {
		return nil, err
	}

	newIdentity := ent.Identity{
		Uid:        uid,
		PrivateKey: privKeyPEM,
		PublicKey:  pubKeyPEM,
		Signature:  make([]byte, i.Protocol.SignatureLength()),
		AuthToken:  auth,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return nil, err
	}

	err = i.Protocol.StoreNewIdentity(tx, newIdentity)
	if err != nil {
		return nil, err
	}

	// register public key at the ubirch backend
	csrPEM, err = i.registerPublicKey(uid, auth)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("commiting transaction to store new identity failed after successful registration at ubirch identity service: %v", err)
	}

	return csrPEM, nil
}

func (i *IdentityHandler) registerPublicKey(uid uuid.UUID, auth string) (csrPEM []byte, err error) {
	keyRegistration, err := i.Protocol.GetSignedKeyRegistration(uid)
	if err != nil {
		return nil, fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, keyRegistration)

	csr, err := i.Protocol.GetCSR(uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.SubmitKeyRegistration(uid, auth, keyRegistration)
	if err != nil {
		return nil, fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
	}

	go i.submitCSROrLogError(uid, csr)

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	return csrPEM, nil
}

func (i *IdentityHandler) submitCSROrLogError(uid uuid.UUID, csr []byte) {
	err := i.SubmitCSR(uid, csr)
	if err != nil {
		log.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}
}

func (i *IdentityHandler) CreateCSR(uid uuid.UUID) (csrPEM []byte, err error) {
	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return nil, fmt.Errorf("could not check if identity is already initialized: %v", err)
	}

	if !initialized {
		return nil, h.ErrUnknown
	}

	_, err = i.Protocol.LoadPrivateKey(uid)
	if err != nil {
		return nil, fmt.Errorf("loading private key for UUID %s failed: %v", uid, err)
	}

	csr, err := i.Protocol.GetCSR(uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	return csrPEM, nil
}
