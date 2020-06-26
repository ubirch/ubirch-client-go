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
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

func registerPublicKey(p *ExtendedProtocol, name string, keyService string) error {
	// get the key
	pubKey, err := p.GetPublicKey(name)
	if err != nil {
		return err
	}

	// get the UUID
	uid, err := p.GetUUID(name)
	if err != nil {
		return err
	}

	// check if the key is already registered at the identity service
	isRegistered, err := isKeyRegistered(keyService, uid, pubKey)
	if err != nil {
		return err
	}

	if !isRegistered {
		log.Printf("%s: registering public key at key service: %s", name, keyService)

		cert, err := getSignedCertificate(p, uid, pubKey)
		if err != nil {
			return fmt.Errorf("error creating public key certificate: %v", err)
		}
		log.Printf("%s: certificate: %s", name, cert)

		code, resp, _, err := post(keyService, cert, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return fmt.Errorf("error sending key registration: %v", err)
		}
		if httpFailed(code) {
			return fmt.Errorf("request to %s failed: (%d) %s", keyService, code, string(resp))
		}

		log.Printf("%s: key registration successful", name)
	}

	return nil
}

// submitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func submitCSR(p *ExtendedProtocol, name string, subjectCountry string, subjectOrganization string, identityService string) error {
	log.Printf("%s: submitting CSR to identity service: %s", name, identityService)

	csr, err := p.GetCSR(name, subjectCountry, subjectOrganization)
	if err != nil {
		return fmt.Errorf("error creating CSR: %v", err)
	}
	log.Printf("%s:   CSR [der]: %s", name, hex.EncodeToString(csr))

	code, resp, _, err := post(identityService, csr, map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if httpFailed(code) {
		return fmt.Errorf("request to %s failed: (%d) %s", identityService, code, string(resp))
	}

	log.Printf("%s: CSR submitted: %s", name, string(resp))

	return nil
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	registered := map[string]bool{}

	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// check if there is a known signing key for the UUID
			if !p.PrivateKeyExists(name) {
				if conf.StaticKeys {
					msg.Response <- HTTPErrorResponse(http.StatusUnauthorized, fmt.Sprintf("dynamic key generation is disabled and there is no injected signing key for UUID %s", name))
					continue
				}

				// if dynamic key generation is enabled generate new key pair
				log.Printf("%s: generating new key pair", name)
				err := p.GenerateKey(name, uid)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: generating new key pair failed: %v", name, err))
					continue
				}

				// store newly generated key in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist new key pair for UUID %s: %v", name, err)
				}
			}

			if _, isRegistered := registered[name]; !isRegistered {
				// register public key at the ubirch backend
				err := registerPublicKey(p, name, conf.KeyService)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: key registration failed: %v", name, err))
					continue
				}

				// submit a X.509 Certificate Signing Request for the public key
				err = submitCSR(p, name, conf.CSR_Country, conf.CSR_Organization, conf.IdentityService)
				if err != nil {
					log.Errorf("%s: submitting CSR failed: %v", name, err)
				} else {
					registered[name] = true
				}
			}

			// create a chained UPP
			log.Printf("%s: signing hash: %s", name, base64.StdEncoding.EncodeToString(msg.Hash[:]))

			upp, err := p.SignHash(name, msg.Hash[:], ubirch.Chained)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error creating UPP for UUID %s: %v", name, err))
				continue
			}
			log.Debugf("%s: UPP: %s (0x%s)", name, base64.StdEncoding.EncodeToString(upp), hex.EncodeToString(upp))

			// send UPP to ubirch backend
			respCode, respBody, respHeaders, err := post(conf.Niomon, upp, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString(msg.Auth),
			})
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error sending UPP to backend: %v", err))
				continue
			}
			log.Debugf("%s: response: (%d) %s (0x%s)", name, respCode, base64.StdEncoding.EncodeToString(respBody), hex.EncodeToString(respBody))

			if httpFailed(respCode) {
				log.Errorf("%s: sending UPP to %s failed: (%d) %q", name, conf.Niomon, respCode, respBody)
				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
			} else {
				// save last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
			}
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load/persist last signature for UUID %s: %v", name, err)
			}

			response, err := json.Marshal(map[string][]byte{"hash": msg.Hash[:], "upp": upp, "response": respBody})
			if err != nil {
				log.Warnf("error serializing extended response: %v", err)
				response = respBody
			} else {
				respHeaders.Del("Content-Length")
				respHeaders.Set("Content-Type", "application/json")
			}
			msg.Response <- HTTPResponse{Code: respCode, Headers: respHeaders, Content: response}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}
