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
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-go-http-server/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type cloudMessage struct {
	uid  uuid.UUID
	name string
	msg  []byte
}

// handle incoming udp messages, create and send a ubirch protocol message (UPP)
func signer(msgHandler chan []byte, respHandler chan api.Response, p *ExtendedProtocol, path string, conf Config, keys map[string]string, ctx context.Context, wg *sync.WaitGroup, db Database) {
	defer wg.Done()

	registeredUUIDs := make(map[uuid.UUID]bool)
	for {
		select {
		case msg := <-msgHandler:
			if len(msg) > 16 {
				uid, err := uuid.FromBytes(msg[:16])
				if err != nil {
					log.Printf("warning: UUID not parsable: (%s) %v\n", hex.EncodeToString(msg[:16]), err)
					continue
				}
				name := uid.String()

				// check if protocol instance has a signing key for UUID
				_, err = p.Crypto.GetPublicKey(name)
				if err != nil {
					// check for inserted keys
					if keys[name] != "" {
						// set private key (public key will automatically be calculated and set)
						keyBytes, err := base64.StdEncoding.DecodeString(keys[name])
						if err != nil {
							log.Printf("Error decoding private key string for %s: %v, string was: %s", name, err, keyBytes)
							continue
						}
						err = p.Crypto.SetKey(name, uid, keyBytes)
						if err != nil {
							log.Printf("Error inserting private key: %v,", err)
							continue
						}
					} else {
						// generate new keypair
						err = p.Crypto.GenerateKey(name, uid)
						if err != nil {
							log.Printf("%s: unable to generate key pair: %v\n", name, err)
							continue
						}
					}
				}

				// check if public key is registered at the key service
				_, registered := registeredUUIDs[uid]
				if !registered {
					cert, err := getSignedCertificate(p, name, uid)
					if err != nil {
						log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
						continue
					}
					log.Printf("CERT [%s]\n", cert)

					_, _, resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"}) // todo handle response code
					if err != nil {
						log.Printf("%s: unable to register public key: %v\n", name, err)
						continue
					}
					log.Printf("%s: registered key: (%d) %v", name, len(resp), string(resp))
					registeredUUIDs[uid] = true
				}

				// send UPP (hash)
				hash := sha256.Sum256(msg[16:])
				log.Printf("%s: hash %s (%s)\n", name,
					base64.StdEncoding.EncodeToString(hash[:]),
					hex.EncodeToString(hash[:]))

				upp, err := p.Sign(name, hash[:], ubirch.Chained)
				if err != nil {
					log.Printf("%s: unable to create UPP: %v\n", name, err)
					continue
				}
				log.Printf("%s: UPP %s\n", name, hex.EncodeToString(upp))

				// save state for every message
				if db != nil {
					err := p.saveDB(db)
					if err != nil {
						log.Printf("unable to save p context in database: %v", err)
					}
				} else {
					err = p.save(path + ContextFile)
					if err != nil {
						log.Printf("unable to save protocol context: %v", err)
					}
				}

				// post UPP to ubirch backend
				code, header, resp, err := post(upp, conf.Niomon, map[string]string{
					"x-ubirch-hardware-id": name,
					"x-ubirch-auth-type":   conf.Auth,
					"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
				})
				if err != nil {
					log.Printf("%s: send failed: %q\n", name, resp)
					continue
				}
				log.Printf("%s: %q\n", name, resp)

				respHandler <- api.Response{Code: code, Header: header, Content: resp}
			}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
