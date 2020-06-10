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
	"io/ioutil"
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

func (p *ExtendedProtocol) verifyUPP(upp []byte, conf Config) (uuid.UUID, []byte, bool, error) {
	o, err := ubirch.DecodeChained(upp)
	if err != nil {
		return uuid.Nil, nil, false, fmt.Errorf("UPP decoding failed: %v", err)
	}
	id := o.Uuid
	name := id.String()

	pubkey, err := p.loadPublicKey(id, conf)
	if err != nil {
		return uuid.Nil, nil, false, fmt.Errorf("loading public key failed: %v", err)
	}

	v, err := p.Verify(name, upp, ubirch.Chained)
	return id, pubkey, v, err
}

func (p *ExtendedProtocol) loadPublicKey(id uuid.UUID, conf Config) ([]byte, error) {
	pubkey, err := p.Crypto.GetPublicKey(id.String())
	if err == nil {
		return pubkey, nil
	}

	url := conf.KeyService + "/current/hardwareId/" + id.String()
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key info: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respContent, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key info from %s failed: (%s) %s", url, resp.Status, string(respContent))
	}

	keys := make([]SignedKeyRegistration, 1)
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}
	err = json.Unmarshal(respBodyBytes, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key registration info: %v", err)
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
	err = p.Crypto.SetPublicKey(id.String(), id, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to set public key in protocol context: %v", err)
	}

	// persist new public key
	err = p.PersistContext()
	if err != nil {
		log.Errorf("unable to persist retrieved public key for UUID %s: %v", id.String(), err)
	}

	return pubKeyBytes, nil
}

// returns the UPP which contains a given hash from the ubirch backend
func loadUPP(hashString string, conf Config) ([]byte, int, error) {
	var resp *http.Response
	var err error

	verificationURL := conf.VerifyService // + "/verify"
	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(verificationURL, "text/plain", strings.NewReader(hashString))
			if err != nil {
				return nil, http.StatusInternalServerError, fmt.Errorf("post request to verification service (%s) failed: %v", verificationURL, err)
			}
			stay = resp.StatusCode != http.StatusOK
			if stay {
				_ = resp.Body.Close()
				log.Printf("Couldn't verify hash yet (%d). Retry... %d", resp.StatusCode, n)
				time.Sleep(time.Second)
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("could not (yet) retrieve certificate for hash %s from verification service (%s): %s", hashString, verificationURL, resp.Status)
	}

	vf := verification{}
	err = json.NewDecoder(resp.Body).Decode(&vf)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to decode verification response: %v", err)
	}
	_ = resp.Body.Close()
	return vf.UPP, resp.StatusCode, nil
}

// hash a message and retrieve corresponding UPP to verify it
func verifier(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:

			hash := msg.Hash
			hashString := base64.StdEncoding.EncodeToString(hash[:])
			log.Printf("verifying hash: %s", hashString)

			upp, code, err := loadUPP(hashString, conf)
			if err != nil {
				msg.Response <- HTTPErrorResponse(code, fmt.Sprintf("verification of hash %s failed! %v", hashString, err))
				continue
			}

			uppString := base64.StdEncoding.EncodeToString(upp)
			log.Debugf("retrieved corresponding UPP for hash %s : %s (0x%s)", hashString, uppString, hex.EncodeToString(upp))

			uid, pubkey, verified, err := p.verifyUPP(upp, conf)
			if !verified {
				code := http.StatusNotFound
				info := fmt.Sprintf("UPP signature verification failed!\n- public key used for verification: %s", base64.StdEncoding.EncodeToString(pubkey))
				if err != nil {
					code = http.StatusInternalServerError
					info = fmt.Sprintf("unable to verify signature: %v", err)
				}
				errMsg := fmt.Sprintf("retrieved corresponding UPP for hash %s but %s\n- UUID: %s\n- UPP: %s", hashString, info, uid.String(), uppString)
				msg.Response <- HTTPErrorResponse(code, errMsg)
				continue
			}

			headers := map[string][]string{"Content-Type": {"application/json"}}
			response, err := json.Marshal(map[string]string{"uuid": uid.String(), "hash": hashString, "upp": uppString})
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
