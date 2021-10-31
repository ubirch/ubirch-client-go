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
	"github.com/ubirch/ubirch-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

type IdentityHandler struct {
	Protocol              *repository.ExtendedProtocol
	SubmitKeyRegistration func(uuid.UUID, []byte) error
	RequestKeyDeletion    func(uuid.UUID, []byte) error
	SubmitCSR             func(uuid.UUID, []byte) error
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

		_, err = i.InitIdentity(uid, auth)
		if err == h.ErrAlreadyInitialized {
			continue
		}
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

	log.Infof("%s: initializing identity", uid)

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

	err = i.Protocol.StoreIdentity(tx, newIdentity)
	if err != nil {
		return nil, err
	}

	// register public key at the ubirch backend
	csrPEM, err = i.registerPublicKey(uid)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("commiting transaction to store new identity failed after successful registration at ubirch identity service: %v", err)
	}

	return csrPEM, nil
}

func (i *IdentityHandler) registerPublicKey(uid uuid.UUID) (csrPEM []byte, err error) {
	keyRegistration, err := i.Protocol.GetSignedKeyRegistration(uid)
	if err != nil {
		return nil, fmt.Errorf("creating public key certificate failed: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, keyRegistration)

	csr, err := i.Protocol.GetCSR(uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR failed: %v", err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.SubmitKeyRegistration(uid, keyRegistration)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("could not check if identity is known: %v", err)
	}

	if !initialized {
		return nil, h.ErrUnknown
	}

	log.Infof("%s: creating CSR", uid)

	csr, err := i.Protocol.GetCSR(uid, i.SubjectCountry, i.SubjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("creating CSR failed: %v", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	return csrPEM, nil
}

func (i *IdentityHandler) DeactivateKey(uid uuid.UUID) error {
	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return fmt.Errorf("could not check if identity is known: %v", err)
	}

	if !initialized {
		return h.ErrUnknown
	}

	log.Infof("%s: deactivating key", uid)

	// update active flag in context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("initializing transaction failed: %v", err)
	}

	active, err := i.Protocol.LoadActiveFlagForUpdate(tx, uid)
	if err != nil {
		return fmt.Errorf("could not load active flag: %v", err)
	}

	if !active {
		return h.ErrAlreadyDeactivated
	}

	err = i.Protocol.StoreActiveFlag(tx, uid, false)
	if err != nil {
		return fmt.Errorf("could not store active flag: %v", err)
	}

	// create self-signed key deletion request for identity service
	keyDeletion, err := i.Protocol.GetSignedKeyDeletion(uid)
	if err != nil {
		return fmt.Errorf("could not create self-signed key deletion request: %v", err)
	}

	// send key deletion request to identity service
	err = i.RequestKeyDeletion(uid, keyDeletion)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("%s: commiting transaction to store active flag failed after successful key deletion at ubirch identity service: %v", uid, err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("deactivate", "device", infos)

	return nil
}

func (i *IdentityHandler) ReactivateKey(uid uuid.UUID) error {
	initialized, err := i.Protocol.IsInitialized(uid)
	if err != nil {
		return fmt.Errorf("could not check if identity is known: %v", err)
	}

	if !initialized {
		return h.ErrUnknown
	}

	log.Infof("%s: reactivating key", uid)

	// update active flag in context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := i.Protocol.StartTransaction(ctx)
	if err != nil {
		return fmt.Errorf("initializing transaction failed: %v", err)
	}

	active, err := i.Protocol.LoadActiveFlagForUpdate(tx, uid)
	if err != nil {
		return fmt.Errorf("could not load active flag: %v", err)
	}

	if active {
		return h.ErrAlreadyActivated
	}

	err = i.Protocol.StoreActiveFlag(tx, uid, true)
	if err != nil {
		return fmt.Errorf("could not store active flag: %v", err)
	}

	// register public key at the ubirch backend
	_, err = i.registerPublicKey(uid)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("%s: commiting transaction to store active flag failed after successful key registration at ubirch identity service: %v", uid, err)
	}

	infos := fmt.Sprintf("\"hwDeviceId\":\"%s\"", uid)
	auditlogger.AuditLog("activate", "device", infos)

	return nil
}
