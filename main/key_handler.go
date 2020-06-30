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
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func registerPublicKey(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte, keyService string) error {
	log.Printf("%s: registering public key at key service: %s", uid.String(), keyService)

	cert, err := getSignedCertificate(p, uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: certificate: %s", uid.String(), cert)

	code, resp, _, err := post(keyService, cert, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if httpFailed(code) {
		return fmt.Errorf("request to %s failed: (%d) %s", keyService, code, string(resp))
	}

	log.Debugf("%s: key registration successful", uid.String())

	return nil
}

// submitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func submitCSR(p *ExtendedProtocol, uid uuid.UUID, subjectCountry string, subjectOrganization string, identityService string) error {
	log.Printf("%s: submitting CSR to identity service: %s", uid.String(), identityService)

	csr, err := p.GetCSR(uid.String(), subjectCountry, subjectOrganization)
	if err != nil {
		return fmt.Errorf("error creating CSR: %v", err)
	}
	log.Debugf("%s: CSR [der]: %s", uid.String(), hex.EncodeToString(csr))

	code, resp, _, err := post(identityService, csr, map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if httpFailed(code) {
		return fmt.Errorf("request to %s failed: (%d) %s", identityService, code, string(resp))
	}

	log.Debugf("%s: CSR submitted: %s", uid.String(), string(resp))

	return nil
}

func initDeviceKeys(p *ExtendedProtocol, conf Config) error {
	for device := range conf.Devices {
		// check if device name is a valid UUID
		uid, err := uuid.Parse(device)
		if err != nil {
			return fmt.Errorf("unable to parse device name \"%s\" as UUID: %s", device, err)
		}
		name := uid.String()

		// check if there is a known signing key for the UUID
		if !p.PrivateKeyExists(name) {
			if conf.StaticKeys {
				return fmt.Errorf("dynamic key generation is disabled and no injected signing key found for UUID %s", name)
			}

			// if dynamic key generation is enabled generate new key pair
			log.Printf("generating new key pair for UUID %s", name)
			err := p.GenerateKey(name, uid)
			if err != nil {
				return fmt.Errorf("generating new key pair for UUID %s failed: %v", name, err)
			}

			// store newly generated key in persistent storage
			err = p.PersistContext()
			if err != nil {
				return fmt.Errorf("unable to persist new key pair for UUID %s: %v", name, err)
			}
		}

		// get the public key
		pubKey, err := p.GetPublicKey(name)
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
			err = registerPublicKey(p, uid, pubKey, conf.KeyService)
			if err != nil {
				return fmt.Errorf("key registration for UUID %s failed: %v", name, err)
			}
		}

		// submit a X.509 Certificate Signing Request for the public key
		err = submitCSR(p, uid, conf.CSR_Country, conf.CSR_Organization, conf.IdentityService)
		if err != nil {
			log.Errorf("submitting CSR for UUID %s failed: %v", name, err)
		}
	}
	return nil
}
