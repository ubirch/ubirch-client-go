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
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-go-c8y-client/c8y"
	"github.com/ubirch/ubirch-protocol-go/ubirch"
	"log"
	"sync"
	"time"
)

// handle incoming udp messages, create and send a ubirch protocol message (UPP)
func signer(handler chan UDPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	registeredUUIDs := make(map[uuid.UUID]bool)
	for {
		select {
		case msg := <-handler:
			log.Printf("signer received %v: %s\n", msg.addr, hex.EncodeToString(msg.data))
			if len(msg.data) > 16 {
				uid, err := uuid.FromBytes(msg.data[:16])
				if err != nil {
					log.Printf("warning: UUID not parsable: (%s) %v\n", hex.EncodeToString(msg.data[:16]), err)
					continue
				}
				name := uid.String()

				// check if certificate exists and generate key pair + registration
				_, err = p.Crypto.GetPublicKey(name)
				if err != nil {
					err = p.Crypto.GenerateKey(name, uid)
					if err != nil {
						log.Printf("%s: unable to generate key pair: %v\n", name, err)
						continue
					}
				}
				_, registered := registeredUUIDs[uid]
				if !registered {
					cert, err := getSignedCertificate(p, name, uid)
					if err != nil {
						log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
						continue
					}
					log.Printf("CERT [%s]\n", cert)

					resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
					if err != nil {
						log.Printf("%s: unable to register public key: %v\n", name, err)
						continue
					}
					log.Printf("%s: registered key: (%d) %v", name, len(resp), string(resp))
					registeredUUIDs[uid] = true
				}

				// send UPP (hash
				hash := sha256.Sum256(msg.data)
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
				err = p.save(ContextFile)
				if err != nil {
					log.Printf("unable to save protocol context: %v", err)
				}

				resp, err := post(upp, conf.Niomon, map[string]string{
					"x-ubirch-hardware-id": name,
					"x-ubirch-auth-type":   conf.Auth,
					"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
				})
				if err != nil {
					log.Printf("%s: send failed: %q\n", name, resp)
					continue
				}
				log.Printf("%s: %q\n", name, resp)

				// create MQTT client for sending values to Cumulocity
				c8yClient, err := c8y.GetClient(name, conf.Cumulocity.Tenant, conf.Cumulocity.Password)
				if err != nil {
					log.Printf("%s: unable to create Cumulocity client: %v\n", name, err)
				}
				defer c8yClient.Disconnect(0)

				// send values to Cumulocity
				switchName1 := "switch1" // FIXME give better names and declare outside loop
				switchName2 := "switch2"
				timestamp := time.Now().UTC()
				err = c8y.Send(c8yClient, switchName1, msg.data[len(msg.data)-2], timestamp)
				if err != nil {
					log.Printf("%s: unable to send value for %s to Cumulocity: %v\n", name, switchName1, err)
				}
				err = c8y.Send(c8yClient, switchName2, msg.data[len(msg.data)-1], timestamp)
				if err != nil {
					log.Printf("%s: unable to send value for %s to Cumulocity: %v\n", name, switchName2, err)
				}
			}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
