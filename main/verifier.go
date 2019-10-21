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
	"github.com/ubirch/ubirch-protocol-go/ubirch"
	"log"
	"sync"
)

// hash a message and retrieve corresponding UPP to verify it
func verifier(handler chan UDPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case msg := <-handler:
			log.Printf("verifier received %v: %s\n", msg.addr, hex.EncodeToString(msg.data))
			if len(msg.data) > 16 {
				uid, err := uuid.FromBytes(msg.data[:16])
				if err != nil {
					log.Printf("warning: UUID not parsable: (%s) %v\n", hex.EncodeToString(msg.data[:16]), err)
					continue
				}
				name := uid.String()

				// check if certificate exists and generate key pair + registration
				_, err = p.Crypto.GetKey(name)
				if err != nil {
					err = p.Crypto.GenerateKey(name, uid)
					if err != nil {
						log.Printf("%s: unable to generate key pair: %v\n", name, err)
						continue
					}
				}

				// create hash to verify
				hash := sha256.Sum256(msg.data)
				log.Printf("%s: hash %s (%s)\n", name,
					base64.StdEncoding.EncodeToString(hash[:]),
					hex.EncodeToString(hash[:]))

				verified, err := p.Verify(name, hash[:], ubirch.Chained)
				if err != nil {
					log.Printf("%s: unable to verify UPP: %v\n", name, err)
					continue
				}
				log.Printf("%s: UPP %s\n", name, verified)

				//resp, err := post(upp, conf.Niomon, map[string]string{
				//	"x-ubirch-hardware-id": name,
				//	"x-ubirch-auth-type":   conf.Auth,
				//	"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
				//})
				//if err != nil {
				//	log.Printf("%s: send failed: %q\n", name, resp)
				//	continue
				//}
				//log.Printf("%s: %q\n", name, resp)

				// save state for every message
				err = p.save(ContextFile)
				if err != nil {
					log.Printf("unable to save protocol context: %v", err)
				}
			}
		case <-ctx.Done():
			log.Println("finishing verifier")
			return
		}
	}
}
