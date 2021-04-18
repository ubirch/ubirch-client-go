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

package main

import (
	"fmt"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	protocol            *ExtendedProtocol
	client              *Client
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) initIdentities(identities map[string]string) error {
	// create and register keys for identities
	log.Infof("initializing %d identities...", len(identities))
	for name, auth := range identities {
		err := i.initIdentity(name, auth)
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *IdentityHandler) initIdentity(name string, auth string) error {
	// make sure identity name is a valid UUID
	uid, err := uuid.Parse(name)
	if err != nil {
		return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
	}

	// make sure identity has an auth token
	if len(auth) == 0 {
		return fmt.Errorf("%s: auth token has zero length", uid)
	}

	err = i.protocol.StartTransaction(uid)
	if err != nil {
		return err
	}
	var success bool
	defer endTransactionOrPanic(i.protocol, uid, success) // todo not sure if this works

	// check if there is a known signing key for the UUID
	if i.protocol.PrivateKeyExists(uid) {
		return nil
	}

	err = i.initKey(uid, auth)
	if err != nil {
		return err
	}

	genesisSignature := make([]byte, i.protocol.SignatureLength())
	err = i.protocol.SetSignature(uid, genesisSignature)
	if err != nil {
		return err
	}

	err = i.protocol.SetAuthToken(uid, auth)
	if err != nil {
		return err
	}

	success = true
	return nil
}

func endTransactionOrPanic(protocol *ExtendedProtocol, uid uuid.UUID, success bool) {
	err := protocol.EndTransaction(uid, success)
	if err != nil {
		log.Panic(err)
	}
}

func (i *IdentityHandler) initKey(uid uuid.UUID, auth string) error {
	// generate new key pair
	log.Printf("generating new key pair for UUID %s", uid)
	err := i.protocol.GenerateKey(uid)
	if err != nil {
		return fmt.Errorf("generating new key pair for UUID %s failed: %v", uid, err)
	}

	// register public key at the ubirch backend
	return i.registerPublicKey(uid, auth)
}

func (i *IdentityHandler) registerPublicKey(uid uuid.UUID, auth string) error {
	pubKey, err := i.protocol.GetPublicKey(uid)
	if err != nil {
		return err
	}
	log.Debugf("%s: public key: %x", uid, pubKey)

	cert, err := i.protocol.GetSignedKeyRegistration(uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: key certificate: %s", uid, cert)

	err = i.client.submitKeyRegistration(uid, cert, auth)
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
	csr, err := i.protocol.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return fmt.Errorf("creating CSR for UUID %s failed: %v", uid, err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	err = i.client.submitCSR(uid, csr)
	if err != nil {
		return fmt.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}
