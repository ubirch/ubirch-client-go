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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	devName    = "dev"
	devUUID    = "9d3c78ff-22f3-4441-a5d1-85c636d486ff"
	devPubKey  = "LnU8BkvGcZQPy5gWVUL+PHA0DP9dU61H8DBO8hZvTyI7lXIlG1/oruVMT7gS2nlZDK9QG+ugkRt/zTrdLrAYDA=="
	demoName   = "demo"
	demoUUID   = "07104235-1892-4020-9042-00003c94b60b"
	demoPubKey = "xm+iIomBRjR3QdvLJrGE1OBs3bAf8EI49FfgBriRk36n4RUYX+0smrYK8tZkl6Lhrt9lzjiUGrXGijRoVE+UjA=="
	prodName   = "prod"
	prodUUID   = "10b2e1a4-56b3-4fff-9ada-cc8c20f93016"
	prodPubKey = "pJdYoJN0N3QTFMBVjZVQie1hhgumQVTy2kX9I7kXjSyoIl40EOa9MX24SBAABBV7xV2IFi1KWMnC1aLOIvOQjQ=="
)

type identity struct {
	Name   string
	UUID   string
	PubKey string
}

func initBackendKeys(p *ExtendedProtocol) error {
	serverIdentities := []identity{
		{Name: devName, UUID: devUUID, PubKey: devPubKey},
		{Name: demoName, UUID: demoUUID, PubKey: demoPubKey},
		{Name: prodName, UUID: prodUUID, PubKey: prodPubKey},
	}

	for _, server := range serverIdentities {
		uid, err := uuid.Parse(server.UUID)
		if err != nil {
			return err
		}
		pkey, err := base64.StdEncoding.DecodeString(server.PubKey)
		if err != nil {
			return err
		}
		err = injectVerificationKey(p, server.Name, uid, pkey)
		if err != nil {
			return err
		}
	}
	return nil
}

func injectVerificationKey(p *ExtendedProtocol, name string, uid uuid.UUID, pubKey []byte) error {
	storedKey, err := p.GetPublicKey(name)
	if err != nil || !bytes.Equal(storedKey, pubKey) {
		log.Debugf("injecting / updating verification key \"%s\": %s", name, base64.StdEncoding.EncodeToString(pubKey))
		err = p.SetPublicKey(name, uid, pubKey)
		if err != nil {
			return err
		}
		return p.PersistContext()
	}
	log.Debugf("found verification key \"%s\": %s", name, base64.StdEncoding.EncodeToString(storedKey))
	return nil
}

func registerPublicKey(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte, keyService string, auth string) error {
	log.Printf("%s: registering public key at key service: %s", uid.String(), keyService)

	cert, err := getSignedCertificate(p, uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: certificate: %s", uid.String(), cert)

	code, resp, _, err := post(keyService, cert, map[string]string{
		"content-type":         "application/json",
		"x-ubirch-hardware-id": uid.String(),
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(auth)),
	})
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if httpFailed(code) {
		return fmt.Errorf("request to %s failed: (%d) %s", keyService, code, string(resp))
	}

	log.Debugf("%s: key registration successful: (%d) %s", uid.String(), code, string(resp))

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

	log.Debugf("%s: CSR submitted: (%d) %s", uid.String(), code, string(resp))

	return nil
}

func initDeviceKeys(p *ExtendedProtocol, conf Config) error {
	err := p.LoadContext() // fails if p not initialized
	if err != nil {
		return fmt.Errorf("unable to load protocol context: %v", err)
	}

	for device, auth := range conf.Devices {
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
			err = registerPublicKey(p, uid, pubKey, conf.KeyService, auth)
			if err != nil {
				return fmt.Errorf("key registration for UUID %s failed: %v", name, err)
			}
		}

		// submit a X.509 Certificate Signing Request for the public key
		err = submitCSR(p, uid, conf.CSR_Country, conf.CSR_Organization, conf.IdentityService)
		if err != nil {
			log.Errorf("submitting CSR for UUID %s failed: %v", name, err)
		}

		//  explicitly set prev. signature to all zeroes in protocol context if UUID does not have a prev. signature
		// in order to be able to reset the prev. signature to all zeroes in case sending of the first UPP fails
		if _, found := p.Signatures[uid]; !found {
			p.Signatures[uid] = make([]byte, 64)

			err = p.PersistContext()
			if err != nil {
				return fmt.Errorf("unable to persist protocol context: %v", err)
			}
		}
	}
	return nil
}
