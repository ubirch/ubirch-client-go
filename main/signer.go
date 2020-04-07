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

	"github.com/google/uuid"
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

	registeredUUIDs := make(map[uuid.UUID]bool)
	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

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
				err = p.Crypto.GenerateKey(name, uid)
				if err != nil {
					log.Printf("%s: unable to generate new key pair: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}
				// persist key
				err = p.PersistKeystore()
				if err != nil {
					log.Printf("%s: unable to store new key pair: %v\n", name, err) // todo is this critical?
				}
			}

			// check if public key is registered at the key service
			if _, registered := registeredUUIDs[uid]; !registered {
				cert, err := getSignedCertificate(p, name, uid)
				if err != nil {
					log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}
				log.Printf("%s: CERT [%s]\n", name, cert)

				code, _, resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
				if err != nil {
					log.Printf("%s: unable to register public key: %v\n", name, err)
					msg.Response <- InternalServerError
					continue
				}
				if code != 200 {
					log.Printf("%s: key registration failed with %d: %q\n", name, code, resp)
					msg.Response <- api.HTTPResponse{
						Code:    code,
						Header:  map[string][]string{"Content-Type": {"text/plain"}},
						Content: []byte(fmt.Sprintf("key registration for %s failed:\n %q\n  %s", name, resp, cert)),
					}
					continue
				}
				log.Printf("%s: registered key: (%d) %v", name, len(resp), string(resp))
				registeredUUIDs[uid] = true
			}

			// send UPP (hash)
			data := msg.Msg
			if !msg.IsAlreadyHashed {
				hash := sha256.Sum256(msg.Msg)
				data = hash[:]
			}
			log.Printf("%s: hash %s (%s)\n", name,
				base64.StdEncoding.EncodeToString(data),
				hex.EncodeToString(data))

			upp, err := p.Sign(name, data, ubirch.Chained)
			if err != nil {
				log.Printf("%s: unable to create UPP: %v\n", name, err)
				msg.Response <- InternalServerError
				continue
			}
			log.Printf("%s: UPP %s\n", name, hex.EncodeToString(upp))

			// post UPP to ubirch backend
			code, header, resp, err := post(upp, conf.Niomon, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
			})
			if err != nil {
				log.Printf("%s: sending UPP to ubirch backend failed: %v\n", name, err)
				msg.Response <- InternalServerError
				continue
			}
			log.Printf("%s: %q\n", name, resp)

			// save last signature after UPP was successfully received in ubirch backend
			if code == 200 {
				err = p.PersistLastSignature(uid)
				if err != nil {
					log.Printf("unable to save protocol context: %v", err)
				}
			} // todo: else reset p.Signatures[id] to prev. signature

			msg.Response <- api.HTTPResponse{Code: code, Header: header, Content: resp}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
