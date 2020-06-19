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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type verification struct {
	UPP     []byte `json:"upp"`
	Prev    []byte `json:"prev"`
	Anchors []byte `json:"anchors"`
}

// loadUPP retrieves the UPP which contains a given hash from the ubirch backend
func loadUPP(hashString string, verifyService string) ([]byte, int, error) {
	var resp *http.Response
	var err error

	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(verifyService, "text/plain", strings.NewReader(hashString))
			if err != nil {
				return nil, http.StatusInternalServerError, fmt.Errorf("error sending verification request: %v", err)
			}
			stay = resp.StatusCode != http.StatusOK
			if stay {
				_ = resp.Body.Close()
				log.Printf("Couldn't verify hash yet (%d). Retry... %d", resp.StatusCode, n)
				time.Sleep(time.Second)
			}
		}
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("could not (yet) retrieve certificate for hash %s from verification service (%s): %s", hashString, verifyService, resp.Status)
	}

	vf := verification{}
	err = json.NewDecoder(resp.Body).Decode(&vf)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to decode verification response: %v", err)
	}
	return vf.UPP, http.StatusOK, nil
}

// verifyUPP verifies the validity of a UPP's signature. Requests public key from the key service if unknown.
func verifyUPP(p *ExtendedProtocol, upp []byte, keyService string) (uuid.UUID, error) {
	o, err := ubirch.DecodeChained(upp)
	if err != nil {
		return uuid.Nil, fmt.Errorf("UPP decoding failed: %v", err)
	}
	id := o.Uuid
	name := id.String()

	pubkey, err := loadPublicKey(p, name, id, keyService)
	if err != nil {
		return id, err
	}
	log.Debugf("verifying validity of UPP signature using pubkey %s of identity %s", base64.StdEncoding.EncodeToString(pubkey), name)

	verified, err := p.Verify(name, upp, ubirch.Chained)
	if err != nil {
		return id, err
	}
	if !verified {
		return id, fmt.Errorf("validity of UPP signature could not be verified using public key %s of identity %s", base64.StdEncoding.EncodeToString(pubkey), name)
	}
	return id, nil
}

// loadPublicKey retrieves the first valid public key associated with an identity from the key service
func loadPublicKey(p *ExtendedProtocol, name string, id uuid.UUID, keyService string) ([]byte, error) {
	pubkey, err := p.GetPublicKey(name)
	if err != nil {
		log.Warnf("couldn't get public key for identity %s from local context", name)
		log.Printf("requesting public key for identity %s from key service: %s", id.String(), keyService)

		keys, err := requestPublicKeys(keyService, id)
		if err != nil {
			return nil, err
		}

		if len(keys) < 1 {
			return nil, fmt.Errorf("no public key for identity %s registered at key service (%s)", id.String(), keyService)
		} else if len(keys) > 1 {
			log.Warnf("several public keys registered for identity %s", id.String())
		}

		log.Printf("retrieved public key for identity %s: %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)

		pubkey, err = base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
		if err != nil {
			return nil, fmt.Errorf("public key not in base64 encoding: %v", err)
		}

		err = p.SetPublicKey(name, id, pubkey)
		if err != nil {
			return nil, fmt.Errorf("unable to set public key in protocol context: %v", err)
		}

		// persist new public key
		err = p.PersistContext()
		if err != nil {
			log.Errorf("unable to persist retrieved public key for UUID %s: %v", name, err)
		}
	}
	return pubkey, nil
}

// verifier retrieves corresponding UPP for a given hash from the ubirch backend and verifies the validity of its signature
func verifier(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:

			hash64 := base64.StdEncoding.EncodeToString(msg.Hash[:])
			log.Printf("%s: verifying", hash64)

			// retrieve corresponding UPP from the ubirch backend
			upp, code, err := loadUPP(hash64, conf.VerifyService)
			if err != nil {
				msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("verification of hash %s failed! %v", hash64, err))
				continue
			}

			upp64 := base64.StdEncoding.EncodeToString(upp)
			log.Debugf("%s: retrieved UPP: %s (0x%s)", hash64, upp64, hex.EncodeToString(upp))

			// verify validity of the retrieved UPP locally
			uid, err := verifyUPP(p, upp, conf.KeyService)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("verification of UPP %s failed! %v", upp64, err))
				continue
			}

			headers := map[string][]string{"Content-Type": {"application/json"}}
			response, err := json.Marshal(map[string]string{"uuid": uid.String(), "hash": hash64, "upp": upp64})
			if err != nil {
				log.Warnf("error serializing extended response: %s", err)
				headers = map[string][]string{"Content-Type": {"application/octet-stream"}}
				response = upp
			}
			msg.Response <- HTTPResponse{Code: code, Headers: headers, Content: response}

		case <-ctx.Done():
			log.Println("finishing verifier")
			return nil
		}
	}
}
