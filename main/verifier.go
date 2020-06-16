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
func loadUPP(verifyService string, hashString string) ([]byte, int, error) {
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

// verifyUPP verifies the validity of a UPP's signature. Requests public key from identity service if unknown.
func (p *ExtendedProtocol) verifyUPP(keyService string, upp []byte) (uuid.UUID, error) {
	o, err := ubirch.DecodeChained(upp)
	if err != nil {
		return uuid.Nil, fmt.Errorf("UPP decoding failed: %v", err)
	}
	id := o.Uuid
	name := id.String()

	pubkey, err := p.GetPublicKey(name)
	if err != nil {
		log.Warnf("couldn't get public key for %s from local context: %s", name, err)

		pubkey, err = loadPublicKey(keyService, id)
		if err != nil {
			return id, fmt.Errorf("loading public key failed: %v", err)
		}

		err = p.SetPublicKey(name, id, pubkey)
		if err != nil {
			return id, fmt.Errorf("unable to set public key in protocol context: %v", err)
		}

		// persist new public key
		err = p.PersistContext()
		if err != nil {
			log.Errorf("unable to persist retrieved public key for UUID %s: %v", name, err)
		}
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

// loadPublicKey retrieves the first valid public key associated with a device from the identity service
func loadPublicKey(keyService string, id uuid.UUID) ([]byte, error) {
	log.Printf("requesting public key for %s from key service: %s", id.String(), keyService)
	keys, err := requestPublicKeys(keyService, id)
	if err != nil {
		return nil, err
	}

	if len(keys) < 1 {
		return nil, fmt.Errorf("no public key found")
	} else if len(keys) > 1 {
		log.Warnf("several public keys registered for device %s", id.String())
	}

	log.Printf("public key (%s): %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		return nil, fmt.Errorf("public key not in base64 encoding: %v", err)
	}

	return pubKeyBytes, nil
}

// verifier retrieves corresponding UPP for a given hash from the ubirch backend and verifies the validity of its signature
func verifier(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:

			hash64 := base64.StdEncoding.EncodeToString(msg.Hash[:])
			log.Printf("%s: verifying", hash64)

			// retrieve corresponding UPP from the ubirch backend
			upp, code, err := loadUPP(conf.VerifyService, hash64)
			if err != nil {
				msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("verification of hash %s failed! %v", hash64, err))
				continue
			}

			upp64 := base64.StdEncoding.EncodeToString(upp)
			log.Debugf("%s: retrieved UPP: %s (0x%s)", hash64, upp64, hex.EncodeToString(upp))

			// verify validity of the retrieved UPP locally
			uid, err := p.verifyUPP(conf.KeyService, upp)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("verification of UPP %s failed! %v", upp64, err))
				continue
			}

			headers := map[string][]string{"Content-Type": {"application/json"}}
			response, err := json.Marshal(map[string]string{"uuid": uid.String(), "hash": hash64, "upp": upp64})
			if err != nil {
				log.Errorf("error serializing extended response: %s", err)
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
