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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func verifyUPP(id uuid.UUID, upp []byte, p *ExtendedProtocol, conf Config) error {
	name := id.String()

	err := p.loadPublicKey(id, conf)
	if err != nil {
		return fmt.Errorf("loading public key for UUID %s failed: %v", name, err)
	}

	verified, err := p.Verify(name, upp, ubirch.Chained)
	if err != nil {
		return fmt.Errorf("unable to verify UPP signature: %v", err)
	}
	if !verified {
		return fmt.Errorf("UPP signature verification failed")
	}
	return nil
}

func (p *ExtendedProtocol) loadPublicKey(id uuid.UUID, conf Config) error {
	_, err := p.Crypto.GetPublicKey(id.String())
	if err == nil {
		return nil
	}

	resp, err := http.Get(conf.KeyService + "/current/hardwareId/" + id.String())
	if err != nil {
		return fmt.Errorf("unable to retrieve public key info for %s: %v", id.String(), err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("retrieving public key info for %s failed: %s", id.String(), resp.Status)
	}

	keys := make([]SignedKeyRegistration, 1)
	decoder := json.NewDecoder(resp.Body)
	_ = resp.Body.Close()

	err = decoder.Decode(&keys)
	if err != nil {
		return fmt.Errorf("unable to decode key registration info: %v", err)
	}

	log.Printf("public key (%s): %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		return fmt.Errorf("public key not in base64 encoding: %v", err)
	}
	err = p.Crypto.SetPublicKey(id.String(), id, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to set public key in protocol context: %v", err)
	}

	// persist new public key
	err = p.PersistContext()
	if err != nil {
		log.Printf("WARNING: unable to persist retrieved public key for UUID %s: %v", id.String(), err)
	}

	return nil
}

// returns the UPP which contains a given hash from the ubirch backend
func loadUPP(hashString string, conf Config) ([]byte, []byte, int, error) {
	var resp *http.Response
	var err error
	url := conf.VerifyService + "/verify"

	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(url, "text/plain", strings.NewReader(hashString))
			if err != nil {
				return nil, nil, http.StatusInternalServerError, fmt.Errorf("post request to verification service (%s) failed: %v", url, err)
			}
			stay = resp.StatusCode != http.StatusOK
			if stay {
				_ = resp.Body.Close()
				log.Printf("Couldn't verify hash yet (%d). Retry... %d\n", resp.StatusCode, n)
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, resp.StatusCode, fmt.Errorf("could not (yet) retrieve certificate for hash %s from verification service (%s): %s", hashString, url, resp.Status)
	}

	vf := verification{}
	err = json.NewDecoder(resp.Body).Decode(&vf)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, fmt.Errorf("unable to decode verification response: %v", err)
	}
	_ = resp.Body.Close()
	return vf.UPP, vf.Prev, resp.StatusCode, nil
}

// hash a message and retrieve corresponding UPP to verify it
func verifier(msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case msg := <-msgHandler:

			hash := msg.Hash
			hashString := base64.StdEncoding.EncodeToString(hash[:])
			log.Printf("verifying hash: %s\n", hashString)

			upp, prev, code, err := loadUPP(hashString, conf)
			if err != nil {
				msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("verification of hash %s failed! %v", hashString, err))
				continue
			}

			uppString := base64.StdEncoding.EncodeToString(upp)
			prevString := base64.StdEncoding.EncodeToString(prev)
			if conf.Debug {
				log.Printf("retrieved corresponding UPP for hash %s : %s (0x%s)", hashString, uppString, hex.EncodeToString(upp))
			}

			o, err := ubirch.DecodeChained(upp)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("retrieved corresponding UPP for hash %s but UPP decoding failed: %v\n UPP: %s", hashString, err, uppString))
				continue
			}

			if bytes.Compare(hash[:], o.Payload) != 0 { // todo this really should not happen!
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "hash and UPP content don't match. retrieved wrong UPP")
				continue
			}

			uid := o.Uuid
			err = verifyUPP(uid, upp, p, conf)
			if err != nil {
				errMsg := fmt.Sprintf("retrieved corresponding UPP for hash %s but UPP verification failed: %v\n- UPP: %s\n- UUID: %s", hashString, err, uppString, uid.String())
				pubkey, _ := p.Crypto.GetPublicKey(uid.String())
				if pubkey != nil {
					errMsg += fmt.Sprintf("\n- used public key: %s", base64.StdEncoding.EncodeToString(pubkey))
				}
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, errMsg)
				continue
			}

			header := map[string][]string{"Content-Type": {"application/json"}}
			response, err := json.Marshal(map[string]string{"uuid": uid.String(), "hash": hashString, "upp": uppString, "prev": prevString})
			if err != nil {
				log.Printf("error serializing extended response: %s", err)
				header = map[string][]string{"Content-Type": {"application/octet-stream"}}
				response = upp
			}
			msg.Response <- HTTPResponse{Code: code, Header: header, Content: response}

		case <-ctx.Done():
			log.Println("finishing verifier")
			return
		}
	}
}
