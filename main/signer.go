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
	"path/filepath"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// check if there is a known signing key for UUID
			if !p.Crypto.PrivateKeyExists(name) {
				if conf.StaticKeys {
					msg.Response <- HTTPErrorResponse(http.StatusUnauthorized, fmt.Sprintf("dynamic key generation is disabled and there is no injected signing key for UUID %s", name))
					continue
				}

				// if dynamic key generation is enabled generate new key pair
				log.Printf("%s: generating new key pair", name)
				err := p.Crypto.GenerateKey(name, uid)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("failed to generate new key pair for UUID %s: %v", name, err))
					continue
				}

				// store newly generated key in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist new key pair for UUID %s: %v", name, err)
				}
			}

			// register public key at the key service
			if _, found := p.Certificates[name]; !found { // if there is no certificate stored yet, the key has not been registered
				log.Printf("%s: registering public key at key service", name)
				// create a self-signed certificate for public key registration
				cert, err := getSignedCertificate(p, name)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("failed to generate signed key certificate for UUID %s: %v", name, err))
					continue
				}
				log.Printf("%s: CERT: %s", name, cert)

				// todo extract method
				keyService := filepath.Join(conf.IdentityService, "/api/keyService/v1/pubkey")
				code, resp, _, err := post(keyService, cert, map[string]string{"Content-Type": "application/json"})
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error sending key registration for UUID %s: %v", name, err))
					continue
				}
				if code != http.StatusOK {
					msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("key registration for UUID %s at key service (%s) failed with response code %d\n key registration message: %s\n key service response: %s", name, keyService, code, cert, string(resp)))
					continue
				}
				log.Printf("%s: key registration successful", name)
				p.Certificates[name] = cert

				// store newly generated certificate in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist new key certificate for UUID %s: %v", name, err)
				}
			}

			// create a X.509 Certificate Signing Request for the public key
			if _, found := p.CSRs[name]; !found { // if there is no CSR stored yet, create one
				log.Printf("%s: creating CSR", name)

				csr, err := p.GetCSR(name, conf.CSR_Country, conf.CSR_Organization)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("failed to create CSR for UUID %s: %v", name, err))
					continue
				}
				log.Printf("%s: CSR [DER]: %s", name, hex.EncodeToString(csr))

				csrService := filepath.Join(conf.IdentityService, "/api/certs/v1/csr/register")
				code, resp, _, err := post(csrService, csr, map[string]string{"Content-Type": "application/octet-stream"})
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error sending CSR for UUID %s: %v", name, err))
					continue
				}
				if code != http.StatusOK {
					msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("sending CSR for for UUID %s to %s failed: (%d) %s", name, csrService, code, string(resp)))
					continue
				}
				log.Printf("%s: CSR successfully sent: %s", name, string(resp))
				p.CSRs[name] = csr

				// store newly generated CSR in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist new CSR for UUID %s: %v", name, err)
				}
			}

			// load last signature for chaining
			err := p.LoadContext()
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load last signature for UUID %s: %v", name, err)
			}

			// create a chained UPP
			hash := msg.Hash
			hashString := base64.StdEncoding.EncodeToString(hash[:])
			log.Printf("%s: signing hash: %s", name, hashString)

			upp, err := p.SignHash(name, hash[:], ubirch.Chained)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error creating UPP for UUID %s: %v", name, err))
				continue
			}

			log.Debugf("%s: UPP: %s (0x%s)", name, base64.StdEncoding.EncodeToString(upp), hex.EncodeToString(upp))

			// send UPP to ubirch backend
			respCode, respBody, respHeaders, err := post(conf.Niomon, upp, map[string]string{
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
				log.Errorf("%s: sending UPP to %s failed: (%d) %q", name, conf.Niomon, respCode, respBody)
				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
			}
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load/persist last signature for UUID %s: %v", name, err)
			}

			extendedResponse, err := json.Marshal(map[string][]byte{"hash": hash[:], "upp": upp, "response": respBody})
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
