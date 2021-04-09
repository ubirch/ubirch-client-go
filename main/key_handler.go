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

func initDeviceKeys(p *ExtendedProtocol, conf Config) error {
	err := p.LoadKeys()
	if err != nil {
		return fmt.Errorf("unable to load protocol context: %v", err)
	}

	// inject keys from configuration to keystore
	err = injectKeys(p, conf.Keys)
	if err != nil {
		return err
	}

	// create and register keys for identities
	for name, auth := range conf.Devices {
		// make sure identity name is a valid UUID
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("invalid identity name \"%s\" (not a UUID): %s", name, err)
		}

		// make sure identity has an auth token
		if auth == "" {
			return fmt.Errorf("no auth token found for identity \"%s\"", name)
		}

		err = setUpKey(p, uid, auth, conf)
		if err != nil {
			return err
		}
	}

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
		err = p.SetKey(name, uid, keyBytes)
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

func setUpKey(p *ExtendedProtocol, uid uuid.UUID, auth string, conf Config) error {
	// check if there is a known signing key for the UUID
	if !p.PrivateKeyExists(uid.String()) {
		if conf.StaticKeys {
			return fmt.Errorf("dynamic key generation is disabled and no injected signing key found for UUID %s", uid)
		}

		// if dynamic key generation is enabled generate new key pair
		log.Printf("generating new key pair for UUID %s", uid)
		err := p.GenerateKey(uid.String(), uid)
		if err != nil {
			return fmt.Errorf("generating new key pair for UUID %s failed: %v", uid, err)
		}

		// store newly generated key in persistent storage
		err = p.PersistKeys()
		if err != nil {
			return fmt.Errorf("unable to persist new key pair for UUID %s: %v", uid, err)
		}
	}

	// get the public key
	pubKey, err := p.GetPublicKey(uid.String())
	if err != nil {
		return err
	}

	// check if the key is already registered at the key service
	isRegistered, err := isKeyRegistered(conf.KeyService, uid, pubKey)
	if err != nil {
		return err
	}

	if !isRegistered {
		// register public key at the ubirch backend
		err = registerPublicKey(p, uid, pubKey, conf.KeyService, auth)
		if err != nil {
			return fmt.Errorf("key registration for UUID %s failed: %v", uid, err)
		}
	}

	// submit a X.509 Certificate Signing Request for the public key
	err = submitCSR(p, uid, conf.CSR_Country, conf.CSR_Organization, conf.IdentityService)
	if err != nil {
		log.Errorf("submitting CSR for UUID %s failed: %v", uid, err)
	}

	return nil
}

func registerPublicKey(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte, keyService string, auth string) error {
	log.Printf("%s: registering public key at key service: %s", uid.String(), keyService)

	cert, err := getSignedCertificate(p, uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: certificate: %s", uid.String(), cert)

	keyRegHeader := ubirchHeader(uid, auth)
	keyRegHeader["content-type"] = "application/json"

	resp, err := post(keyService, cert, keyRegHeader)
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if httpFailed(resp.StatusCode) {
		return fmt.Errorf("request to %s failed: (%d) %q", keyService, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: key registration successful: (%d) %s", uid.String(), resp.StatusCode, string(resp.Content))
	return nil
}

// submitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func submitCSR(p *ExtendedProtocol, uid uuid.UUID, subjectCountry string, subjectOrganization string, identityService string) error {
	log.Printf("%s: submitting CSR to identity service: %s", uid.String(), identityService)

	csr, err := p.GetCSR(uid.String(), subjectCountry, subjectOrganization)
	if err != nil {
		return fmt.Errorf("error creating CSR: %v", err)
	}
	log.Debugf("%s: CSR [der]: %x", uid.String(), csr)

	CSRHeader := map[string]string{"content-type": "application/octet-stream"}

	resp, err := post(identityService, csr, CSRHeader)
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if httpFailed(resp.StatusCode) {
		return fmt.Errorf("request to %s failed: (%d) %q", identityService, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: CSR submitted: (%d) %s", uid.String(), resp.StatusCode, string(resp.Content))
	return nil
}
