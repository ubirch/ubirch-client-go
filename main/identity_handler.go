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
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type IdentityHandler struct {
	protocol            *ExtendedProtocol
	staticKeys          bool
	identityService     string
	keyService          string
	subjectCountry      string
	subjectOrganization string
}

func (i *IdentityHandler) initIdentities(keys map[string]string, identities map[string]string) error {
	// inject keys from configuration to keystore
	err := injectKeys(i.protocol, keys)
	if err != nil {
		return err
	}

	// create and register keys for identities
	log.Infof("initializing %d identities...", len(identities))
	for name, auth := range identities {
		err = i.initIdentity(name, auth)
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

	err = i.protocol.PersistAuthToken(uid, auth)

	err = i.setUpKey(uid, auth)
	if err != nil {
		return err
	}

	return nil
}

func (i *IdentityHandler) setUpKey(uid uuid.UUID, auth string) error {
	// check if there is a known signing key for the UUID
	if !i.protocol.PrivateKeyExists(uid) {
		if !i.staticKeys {
			return fmt.Errorf("dynamic key generation is disabled")
		}

		// if dynamic key generation is enabled generate new key pair
		log.Printf("generating new key pair for UUID %s", uid)
		err := i.protocol.GenerateKey(uid)
		if err != nil {
			return fmt.Errorf("generating new key pair for UUID %s failed: %v", uid, err)
		}

		// store newly generated key in persistent storage
		err = i.protocol.PersistKeys()
		if err != nil {
			return fmt.Errorf("unable to persist new key pair for UUID %s: %v", uid, err)
		}
	}

	// get the public key
	pubKey, err := i.protocol.GetPublicKey(uid)
	if err != nil {
		return err
	}

	// check if the key is already registered at the key service
	isRegistered, err := isKeyRegistered(i.keyService, uid, pubKey)
	if err != nil {
		return err
	}

	if !isRegistered {
		// register public key at the ubirch backend
		err = registerPublicKey(i.protocol, uid, pubKey, i.keyService, auth)
		if err != nil {
			return fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
		}
	}

	// submit a X.509 Certificate Signing Request for the public key
	go func(_uid uuid.UUID) {
		err := i.submitCSR(_uid)
		if err != nil {
			log.Errorf("submitting CSR for UUID %s failed: %v", _uid, err)
		}
	}(uid)

	return nil
}

// submitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func (i *IdentityHandler) submitCSR(uid uuid.UUID) error {
	log.Debugf("%s: submitting CSR to identity service", uid)

	csr, err := i.protocol.GetCSR(uid, i.subjectCountry, i.subjectOrganization)
	if err != nil {
		return fmt.Errorf("error creating CSR: %v", err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	CSRHeader := map[string]string{"content-type": "application/octet-stream"}

	resp, err := post(i.identityService, csr, CSRHeader)
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if httpFailed(resp.StatusCode) {
		return fmt.Errorf("request to %s failed: (%d) %q", i.identityService, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: CSR submitted: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

func injectKeys(p *ExtendedProtocol, keys map[string]string) error {
	for name, key := range keys {
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("unable to parse key name %s from key map to UUID: %v", name, err)
		}
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("unable to decode private key string for %s: %v, string was: %s", name, err, key)
		}
		err = p.SetKey(uid, keyBytes)
		if err != nil {
			return fmt.Errorf("unable to inject key to keystore: %v", err)
		}
		err = p.PersistKeys()
		if err != nil {
			return fmt.Errorf("unable to persist injected key for UUID %s: %v", uid, err)
		}
	}
	return nil
}
