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
	"encoding/binary"
	"encoding/hex"
	"github.com/eclipse/paho.mqtt.golang"
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
	mqttClients := make(map[uuid.UUID]mqtt.Client)
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

				// send switch states to Cumulocity
				client := mqttClients[uid]
				if client == nil {
					// create MQTT client for sending values to Cumulocity
					client, err = c8y.GetClient(name, conf.C8yTenant, "")
					if err != nil {
						log.Printf("%s: unable to create Cumulocity client: %v\n", name, err)
						continue
					}
					defer client.Disconnect(0)
					mqttClients[uid] = client
				}
				timestamp := time.Unix(0, int64(binary.LittleEndian.Uint64(msg.data[16:24]))).UTC()
				err = c8y.Send(client, name+"-A", msg.data[24], timestamp)
				if err != nil {
					log.Printf("%s: unable to send value for %s to Cumulocity: %v\n", name, name+"A", err)
					continue
				}
				err = c8y.Send(client, name+"-B", msg.data[25], timestamp)
				if err != nil {
					log.Printf("%s: unable to send value for %s to Cumulocity: %v\n", name, name+"B", err)
					continue
				}

				// post UPP to ubirch backend
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

			}
		case <-ctx.Done():
			log.Println("finishing signer")
			return
		}
	}
}
