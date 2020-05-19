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

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	const errID = "SIGNER ERROR"

	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// check if there is a known signing key for UUID
			if !p.Crypto.PrivateKeyExists(name) {
				if conf.StaticKeys {
					msg.Response <- HTTPErrorResponse(http.StatusUnauthorized, fmt.Sprintf("%s: dynamic key generation is disabled and there is no injected signing key for UUID %s", errID, name))
					continue
				}

				// if dynamic key generation is enabled generate new key pair
				log.Printf("%s: generating new key pair", name)
				err := p.Crypto.GenerateKey(name, uid)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: generating new key pair for UUID %s failed: %v", errID, name, err))
					continue
				}

				// store newly generated key in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					log.Fatalf("%s: unable to store new key pair for UUID %s: %v", errID, name, err)
				}
			}

			// check if public key is registered at the key service
			if _, found := p.Certificates[name]; !found { // if there is no certificate stored yet, the key has not been registered
				log.Printf("%s: registering public key at key service", name)
				// create a signed certificate for public key registration
				cert, err := getSignedCertificate(p, name)
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: generating signed key certificate for UUID %s failed: %v", errID, name, err))
					continue
				}
				log.Printf("%s: CERT: %s\n", name, cert)

				code, _, resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json; charset=utf-8"})
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: sending key registration message for UUID %s failed: %v", errID, name, err))
					continue
				}
				if code != http.StatusOK {
					msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("%s: key registration for UUID %s at key service (%s) failed. (%d)\n key registration message: %s\n key service response: %s", errID, name, conf.KeyService, code, cert, string(resp)))
					continue
				}
				log.Printf("%s: key registration successful", name)
				p.Certificates[name] = cert

				// store newly generated certificate in persistent storage
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					log.Fatalf("%s: unable to store new key certificate for UUID %s: %v", errID, name, err)
				}
			}

			// load last signature for chaining
			err := p.LoadContext()
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				log.Fatalf("%s: unable to load last signature for UUID %s: %v", errID, name, err)
			}

			// create a chained UPP
			hash := msg.Hash
			hashString := base64.StdEncoding.EncodeToString(hash[:])
			log.Printf("%s: signing hash: %s", name, hashString)

			upp, err := p.SignHash(name, hash[:], ubirch.Chained)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: error creating UPP for UUID %s: %v", errID, name, err))
				continue
			}

			uppString := base64.StdEncoding.EncodeToString(upp)
			if conf.Debug {
				log.Printf("%s: UPP: %s (0x%s)", name, uppString, hex.EncodeToString(upp))
			}

			// send UPP to ubirch backend
			code, header, resp, err := post(upp, conf.Niomon, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Devices[name])),
			})
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("%s: error sending UPP for UUID %s to ubirch backend: %v", errID, name, err))
				continue
			}
			if conf.Debug {
				log.Printf("%s: response: (%d) %s (0x%s)", name, code, base64.StdEncoding.EncodeToString(resp), hex.EncodeToString(resp))
			}

			// save last signature after UPP was successfully received in ubirch backend
			if code != http.StatusOK {
				log.Printf("%s: sending UPP to %s failed: (%d) %q", name, conf.Niomon, code, resp)
			} else {
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					log.Fatalf("%s: unable to save last signature for UUID %s: %v", errID, name, err)
				}
			}

			// TODO verify response UPP using ECDSA backend public key (not implemented yet)

			// decode response UPP
			var respContent string
			if resp[1] == byte(ubirch.Signed) {
				var respDecoded ubirch.SignedUPP
				respDecoded, err = ubirch.DecodeSigned(resp)
				respContent = string(respDecoded.Payload)
			} else if resp[1] == byte(ubirch.Chained) {
				var respDecoded ubirch.ChainedUPP
				respDecoded, err = ubirch.DecodeChained(resp)
				respContent = string(respDecoded.Payload)
			}
			if respContent == "" {
				log.Printf("%s: response UPP decoding failed: %v", name, err)
				respContent = base64.StdEncoding.EncodeToString(resp)
			}

			extendedResponse, err := json.Marshal(map[string]string{"hash": hashString, "upp": uppString, "response": respContent})
			if err == nil {
				header = map[string][]string{"Content-Type": {"application/json"}}
			} else {
				log.Printf("error serializing extended response: %s", err)
				extendedResponse = resp
			}
			msg.Response <- HTTPResponse{Code: code, Header: header, Content: extendedResponse}

		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
