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

func registerPublicKey(p *ExtendedProtocol, identityService string, name string, subjectCountry string, subjectOrganization string) ([]byte, error) {
	// get the key
	pubKey, err := p.GetPublicKey(name)
	if err != nil {
		return nil, err
	}

	// get the UUID
	uid, err := p.GetUUID(name)
	if err != nil {
		return nil, err
	}

	// check if key is already registered at the identity service
	isRegistered, err := isKeyRegistered(identityService, uid, pubKey)
	if err != nil {
		return nil, err
	}

	if !isRegistered {
		log.Printf("%s: registering public key at identity service", name)

		// submit a X.509 Certificate Signing Request for the public key
		_, err = submitCSR(p, identityService, name, subjectCountry, subjectOrganization)
		if err != nil {
			return nil, err
		}

		// create a self-signed certificate for the public key registration
		cert, err := getSignedCertificate(p, name, uid)
		if err != nil {
			return nil, fmt.Errorf("error creating public key certificate: %v", err)
		}
		log.Printf("%s: CERT: %s", name, cert)

		keyService := identityService + "/api/keyService/v1/pubkey"
		code, resp, _, err := post(keyService, cert, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return nil, fmt.Errorf("error sending key registration: %v", err)
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("key registration at %s failed: (%d) %s", keyService, code, string(resp))
		}
		log.Printf("%s: key registration successful", name)
	}

	return pubKey, nil
}

func submitCSR(p *ExtendedProtocol, identityService string, name string, subjectCountry string, subjectOrganization string) ([]byte, error) {
	log.Printf("%s: submitting CSR to identity service", name)

	csr, err := p.GetCSR(name, subjectCountry, subjectOrganization)
	if err != nil {
		return nil, fmt.Errorf("error creating CSR: %v", err)
	}
	log.Printf("%s: CSR [DER]: %s", name, hex.EncodeToString(csr))

	csrService := identityService + "/api/certs/v1/csr/register"
	code, resp, _, err := post(csrService, csr, map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return nil, fmt.Errorf("error sending CSR: %v", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("submitting CSR to %s failed: (%d) %s", csrService, code, string(resp))
	}
	log.Printf("%s: CSR successfully sent: %s", name, string(resp))

	return csr, nil
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	registeredKeys := map[string][]byte{}

	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// check if there is a known signing key for UUID
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

			// register public key at the identity service
			if _, found := registeredKeys[name]; !found {
				pubKey, err := registerPublicKey(p, conf.IdentityService, name, conf.CSR_Country, conf.CSR_Organization)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: %v", name, err))
					continue
				}
				registeredKeys[name] = pubKey
			}

			// load last signature for chaining
			err := p.LoadContext()
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load last signature for UUID %s: %v", name, err)
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
			authService := conf.Niomon + "/"
			respCode, respBody, respHeaders, err := post(authService, upp, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Devices[name])),
			})
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error sending UPP to backend: %v", err))
				continue
			}
			log.Debugf("%s: response: (%d) %s (0x%s)", name, respCode, base64.StdEncoding.EncodeToString(respBody), hex.EncodeToString(respBody))

			if respCode == http.StatusOK {
				// save last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
			} else {
				log.Errorf("%s: sending UPP to %s failed: (%d) %q", name, authService, respCode, respBody)
				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
			}
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load/persist last signature for UUID %s: %v", name, err)
			}

			extendedResponse, err := json.Marshal(map[string][]byte{"hash": msg.Hash[:], "upp": upp, "response": respBody})
			if err != nil {
				log.Warnf("error serializing extended response: %v", err)
				extendedResponse = respBody
			} else {
				respHeaders.Del("Content-Length")
				respHeaders.Set("Content-Type", "application/json")
			}
			msg.Response <- HTTPResponse{Code: respCode, Headers: respHeaders, Content: extendedResponse}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}
