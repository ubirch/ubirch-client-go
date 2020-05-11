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
	"log"
	"net/http"
	"sync"

	"github.com/ubirch/ubirch-client-go/main/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func internalServerError(message string) api.HTTPResponse {
	if message == "" {
		message = http.StatusText(http.StatusInternalServerError)
	}
	return api.HTTPResponse{
		Code:    http.StatusInternalServerError,
		Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		Content: []byte(message),
	}
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(msgHandler chan api.HTTPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// check if there is a known signing key for UUID
			if !p.Crypto.PrivateKeyExists(name) {
				if conf.StaticKeys {
					log.Printf("%s: dynamic key generation is disabled and there is no injected signing key for UUID\n", name)
					msg.Response <- api.HTTPResponse{
						Code:    http.StatusUnauthorized,
						Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
						Content: []byte(fmt.Sprintf("dynamic key generation is disabled and there is no known signing key for UUID %s", name)),
					}
					continue
				}

				// if dynamic key generation is enabled generate new key pair
				log.Printf("%s: generating new key pair\n", name)
				err := p.Crypto.GenerateKey(name, uid)
				if err != nil {
					log.Printf("%s: error generating new key pair: %v\n", name, err)
					msg.Response <- internalServerError(fmt.Sprintf("error generating new key pair: %v", err))
					continue
				}

				// store newly generated key in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- internalServerError("")
					log.Fatalf("%s: unable to store new key pair: %v\n", name, err)
				}
			}

			// check if public key is registered at the key service
			if _, found := p.Certificates[name]; !found { // if there is no certificate stored yet, the key has not been registered
				log.Printf("%s: registering public key at key service\n", name)
				// create a signed certificate for public key registration
				cert, err := getSignedCertificate(p, name)
				if err != nil {
					log.Printf("%s: error generating signed key certificate: %v\n", name, err)
					msg.Response <- internalServerError(fmt.Sprintf("error generating signed key certificate: %v", err))
					continue
				}
				log.Printf("%s: CERT: %s\n", name, cert)

				code, _, resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json; charset=utf-8"})
				if err != nil {
					log.Printf("%s: error sending key registration message: %v\n", name, err)
					msg.Response <- internalServerError(fmt.Sprintf("error sending key registration message: %v", err))
					continue
				}
				if code != 200 {
					log.Printf("%s: sending key registration message to %s failed: %d: %s\n", name, conf.KeyService, code, string(resp))
					msg.Response <- api.HTTPResponse{
						Code:    code,
						Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
						Content: []byte(fmt.Sprintf("sending key registration message for UUID %s to %s failed.\n key registration message: %s\n key service response: %s", name, conf.KeyService, cert, string(resp))),
					}
					continue
				}
				log.Printf("%s: key registration successful", name)
				p.Certificates[name] = cert

				// store newly generated certificate in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- internalServerError("")
					log.Fatalf("%s: unable to store new key certificate: %v\n", name, err)
				}
			}

			// load last signature for chaining
			err := p.LoadContext()
			if err != nil {
				msg.Response <- internalServerError("")
				log.Fatalf("unable to load last signature: %v", err)
			}

			// create a chained UPP
			hash := msg.Hash
			log.Printf("%s: hash: %s\n", name, base64.StdEncoding.EncodeToString(hash[:]))

			upp, err := p.SignHash(name, hash[:], ubirch.Chained)
			if err != nil {
				log.Printf("%s: error creating UPP: %v\n", name, err)
				msg.Response <- internalServerError(fmt.Sprintf("error creating UPP: %v", err))
				continue
			}
			if conf.Debug {
				log.Printf("%s:  UPP: %s\n", name, hex.EncodeToString(upp))
			}

			// send UPP to ubirch backend
			code, header, resp, err := post(upp, conf.Niomon, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Devices[name])),
			})
			if err != nil {
				log.Printf("%s: error sending UPP to ubirch backend: %v\n", name, err)
				msg.Response <- internalServerError(fmt.Sprintf("error sending UPP to ubirch backend: %v", err))
				continue
			}
			if conf.Debug {
				log.Printf("%s: response: (%d) %s\n", name, code, hex.EncodeToString(resp))
			}

			// save last signature after UPP was successfully received in ubirch backend
			if code == 200 {
				err = p.PersistContext()
				if err != nil {
					msg.Response <- internalServerError("")
					log.Fatalf("unable to save last signature: %v", err)
				}
			} else {
				log.Printf("%s: sending UPP to %s failed: (%d) %q\n", name, conf.Niomon, code, resp)
			}

			extendedResponse, err := json.Marshal(map[string][]byte{"hash": hash[:], "upp": upp, "response": resp})
			if err != nil {
				log.Printf("error serializing extended response: %s", err)
				extendedResponse = resp
			}
			header = map[string][]string{"Content-Type": {"application/json; charset=utf-8"}}

			msg.Response <- api.HTTPResponse{Code: code, Header: header, Content: extendedResponse}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
