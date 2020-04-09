/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/ubirch/ubirch-go-http-server/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var InternalServerError = api.HTTPResponse{
	Code:    http.StatusInternalServerError,
	Header:  map[string][]string{"Content-Type": {"text/plain"}},
	Content: []byte(http.StatusText(http.StatusInternalServerError)),
}

// handle incoming udp messages, create and send a ubirch protocol message (UPP)
func signer(msgHandler chan api.HTTPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()
			log.Printf("%s: signer received request\n", name)

			// check if there is a known signing key for UUID
			_, err := p.Crypto.GetPublicKey(name)
			if err != nil {
				if conf.StaticUUID {
					log.Printf("%s: dynamic key generation is disabled and there is no known signing key for UUID\n", name)
					msg.Response <- api.HTTPResponse{
						Code:    http.StatusUnauthorized,
						Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
						Content: []byte(fmt.Sprintf("dynamic key generation is disabled and there is no known signing key for UUID %s", name)), // todo TMI?
					}
					continue
				}

				// if dynamic key generation is enabled generate new key pair
				log.Printf("%s: generating new key pair\n", name)
				err = p.Crypto.GenerateKey(name, uid)
				if err != nil {
					log.Printf("%s: unable to generate new key pair: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}

				// store newly generated key in persistent storage
				err = p.PersistContext()
				if err != nil {
					log.Printf("%s: unable to store new key pair: %v\n", name, err) // todo is this critical?
				}
			}

			// check if public key is registered at the key service
			if _, found := p.Certificates[name]; !found { // if there is no certificate stored yet, the key has not been registered
				log.Printf("%s: registering public key at key service\n", name)
				// create a signed certificate for public key registration
				cert, err := getSignedCertificate(p, name)
				if err != nil {
					log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}
				log.Printf("%s: CERT: %s\n", name, cert)

				code, _, resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
				if err != nil {
					log.Printf("%s: unable to register public key: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}
				if code != 200 {
					log.Printf("%s: key registration failed with %d: %s\n", name, code, string(resp))
					msg.Response <- api.HTTPResponse{
						Code:    code,
						Header:  map[string][]string{"Content-Type": {"text/plain"}},
						Content: []byte(fmt.Sprintf("key registration for UUID %s failed.\n key registration message: %s\n key service response: %s", name, cert, string(resp))),
					}
					continue
				}
				log.Printf("%s: key registration successful: %v", name, string(resp))
				p.Certificates[name] = cert

				// store newly generated certificate in persistent storage
				err = p.PersistContext()
				if err != nil {
					log.Printf("unable to save protocol context: %v", err)
				}
			}

			// send UPP (hash)
			data := msg.Msg
			if !msg.IsAlreadyHashed {
				hash := sha256.Sum256(msg.Msg)
				data = hash[:]
			}
			log.Printf("%s: hash: %s (%s)\n", name,
				base64.StdEncoding.EncodeToString(data),
				hex.EncodeToString(data))

			// todo insert last signature from persistent storage to protocol instance (lock resource)
			upp, err := p.SignHash(name, data, ubirch.Chained)
			if err != nil {
				log.Printf("%s: unable to create UPP: %v\n", name, err)
				msg.Response <- InternalServerError
				continue
			}
			log.Printf("%s: UPP: %s\n", name, hex.EncodeToString(upp))

			// post UPP to ubirch backend
			code, header, resp, err := post(upp, conf.Niomon, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Devices[name])),
			})
			if err != nil {
				log.Printf("%s: sending UPP to ubirch backend failed: %v\n", name, err)
				msg.Response <- InternalServerError
				continue
			}
			log.Printf("%s: response: (%d) %s\n", name, code, string(resp))

			// save last signature after UPP was successfully received in ubirch backend
			if code == 200 {
				err = p.PersistContext() // todo err = p.PersistLastSignature(uid)
				if err != nil {
					log.Printf("unable to save last signature: %v", err)
				}
			}
			// todo free resource when done or if sthg went wrong

			msg.Response <- api.HTTPResponse{Code: code, Header: header, Content: resp}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
