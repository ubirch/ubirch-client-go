//+build never

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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type verification struct {
	UPP     []byte `json:"upp"`
	Prev    []byte `json:"prev"`
	Anchors []byte `json:"anchors"`
}

func (p *ExtendedProtocol) checkAndRetrieveKey(id uuid.UUID, conf Config) error {
	_, err := p.Crypto.GetPublicKey(id.String())
	if err == nil {
		return nil
	}

	resp, err := http.Get(conf.KeyService + "/current/hardwareId/" + id.String())
	if err != nil {
		log.Printf("unable to retrieve public key info for %s: %v", id.String(), resp)
		return err
	}

	keys := make([]SignedKeyRegistration, 1)
	decoder := json.NewDecoder(resp.Body)
	_ = resp.Body.Close()

	err = decoder.Decode(&keys)
	if err != nil {
		log.Printf("unable to decode key registration info: %v", err)
		return err
	}

	log.Printf("public key (%s): %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		log.Printf("public key not in base64 encoding: %v", err)
		return err
	}
	err = p.Crypto.SetPublicKey(id.String(), id, pubKeyBytes)
	if err != nil {
		log.Printf("unable to store public key: %v", err)
		return err
	}

	return nil
}

func loadUPP(hash [32]byte, conf Config) ([]byte, error) {
	hashString := base64.StdEncoding.EncodeToString(hash[:])
	log.Printf("checking hash %s", hashString)
	// a slight initial delay
	time.Sleep(300 * time.Millisecond)

	var resp *http.Response
	var err error

	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(conf.VerifyService, "text/plain", strings.NewReader(hashString))
			if err != nil {
				log.Printf("network error: unable to retrieve data certificate: %v", err)
				break
			}
			stay = resp.StatusCode != http.StatusOK
			if stay {
				_ = resp.Body.Close()
				log.Printf("Couldn't verify hash yet (%d). Retry... %d\n", resp.StatusCode, n)
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("unable to retrieve data certificate: response code %s", resp.Status)
		return nil, errors.New(resp.Status)
	}

	vf := verification{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&vf)
	if err != nil {
		log.Printf("unable to decode verification response: %v", err)
		return nil, err
	}
	_ = resp.Body.Close()
	upp := vf.UPP
	log.Printf("UPP: %s", hex.EncodeToString(upp))
	return upp, nil
}

const (
	OkVerified         = 0x00
	ErrUuidInvalid     = 0xE0
	ErrUppNotFound     = 0xE1
	ErrKeyNotFound     = 0xE2
	ErrSigFailed       = 0xF0
	ErrSigInvalid      = 0xF1
	ErrUppDecodeFailed = 0xF2
	ErrHashMismatch    = 0xF3
)

// hash a message and retrieve corresponding UPP to verify it
func verifier(handler chan []byte, responseHandler chan []byte, p *ExtendedProtocol, path string, conf Config, ctx context.Context, wg *sync.WaitGroup, db Database) {
	defer wg.Done()

	sendResponse := func(data []byte, code byte) {
		responseHandler <- append(data, code)
	}

	for {
		select {
		case msg := <-handler:

			if len(msg) > 16 {
				uid, err := uuid.FromBytes(msg[:16])
				if err != nil {
					log.Printf("warning: UUID not parsable: (%s) %v\n", hex.EncodeToString(msg[:16]), err)
					sendResponse(msg, ErrUuidInvalid)
					continue
				}
				name := uid.String()

				hash := sha256.Sum256(msg)
				upp, err := loadUPP(hash, conf)
				if err != nil {
					log.Printf("%s: unable to load corresponding UPP: %v", name, err)
					sendResponse(msg, ErrUppNotFound)
					continue
				}

				// check if we already have the key, otherwise try to retrieve it
				err = p.checkAndRetrieveKey(uid, conf)
				if err != nil {
					log.Printf("%s: unable to find key: %v", name, err)
					sendResponse(msg, ErrKeyNotFound)
					continue
				}

				verified, err := p.Verify(name, upp, ubirch.Chained)
				if err != nil {
					log.Printf("%s: unable to verify UPP signature: %v\n", name, err)
					sendResponse(msg, ErrSigFailed)
					continue
				}
				if !verified {
					log.Printf("%s: failed to verify UPP signature", name)
					sendResponse(msg, ErrSigInvalid)
					continue
				}

				o, err := ubirch.Decode(upp)
				if err != nil {
					log.Printf("decoding UPP failed, can't check validity: %v", err)
					sendResponse(msg, ErrUppDecodeFailed)
					continue
				}
				// do a final consistency check and compare the msg hash with the one in the UPP
				if bytes.Compare(hash[:], o.(*ubirch.ChainedUPP).Payload) != 0 {
					log.Printf("hash and UPP content don't match: invalid request")
					sendResponse(msg, ErrHashMismatch)
					continue
				}

				// the request has been checked and is okay
				log.Printf("verified and valid request received: %s", hex.EncodeToString(msg))
				sendResponse(msg, OkVerified)

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
			}
		case <-ctx.Done():
			log.Println("finishing verifier")
			return
		}
	}
}
