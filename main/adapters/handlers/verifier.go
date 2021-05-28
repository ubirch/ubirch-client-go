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

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
)

type verification struct {
	UPP     []byte `json:"upp"`
	Prev    []byte `json:"prev"`
	Anchors []byte `json:"anchors"`
}

type verificationResponse struct {
	Error  string `json:"error,omitempty"`
	Hash   []byte `json:"hash,omitempty"`
	UPP    []byte `json:"upp,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	PubKey []byte `json:"pubKey,omitempty"`
}

type Verifier struct {
	Protocol                      *repository.ExtendedProtocol
	VerifyFromKnownIdentitiesOnly bool
}

func (v *Verifier) Verify(hash []byte) h.HTTPResponse {
	log.Infof("verifying hash %s", base64.StdEncoding.EncodeToString(hash))

	// retrieve certificate for hash from the ubirch backend
	code, upp, err := v.loadUPP(hash)
	if err != nil {
		log.Error(err)
		return errorResponse(code, err.Error())
	}
	log.Debugf("retrieved UPP %x", upp)

	// verify validity of the retrieved UPP locally
	id, pkey, err := v.verifyUPP(upp)
	if err != nil {
		return getVerificationResponse(http.StatusUnprocessableEntity, hash, upp, id, pkey, err.Error())
	}
	log.Debugf("verified UPP from identity %s using public key %s", id, base64.StdEncoding.EncodeToString(pkey))

	return getVerificationResponse(http.StatusOK, hash, upp, id, pkey, "")
}

// loadUPP retrieves the UPP which contains a given hash from the ubirch backend
func (v *Verifier) loadUPP(hash []byte) (int, []byte, error) {
	var resp h.HTTPResponse
	var err error
	hashBase64String := base64.StdEncoding.EncodeToString(hash)

	n := 0
	for stay, timeout := true, time.After(3*time.Second); stay; {
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = v.Protocol.Post(v.Protocol.VerifyServiceURL, []byte(hashBase64String), map[string]string{"content-type": "text/plain"})
			if err != nil {
				return http.StatusInternalServerError, nil, fmt.Errorf("error sending verification request: %v", err)
			}
			stay = h.HttpFailed(resp.StatusCode)
			if stay {
				log.Debugf("Couldn't verify hash yet (%d). Retry... %d", resp.StatusCode, n)
				time.Sleep(500 * time.Millisecond)
			}
		}
	}

	if h.HttpFailed(resp.StatusCode) {
		return resp.StatusCode, nil, fmt.Errorf("could not retrieve certificate for hash %s from UBIRCH verification service: (%d) %s", hashBase64String, resp.StatusCode, string(resp.Content))
	}

	vf := verification{}
	err = json.Unmarshal(resp.Content, &vf)
	if err != nil {
		return http.StatusBadGateway, nil, fmt.Errorf("unable to decode verification response: %v", err)
	}
	return resp.StatusCode, vf.UPP, nil
}

// verifyUPP verifies the signature of UPPs from known identities using their public keys from the local keystore
func (v *Verifier) verifyUPP(upp []byte) (uuid.UUID, []byte, error) {
	uppStruct, err := ubirch.Decode(upp)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("retrieved invalid UPP: %v", err)
	}

	id := uppStruct.GetUuid()

	pubKeyPEM, err := v.Protocol.GetPublicKey(id)
	if err != nil {
		if v.VerifyFromKnownIdentitiesOnly {
			return id, nil, fmt.Errorf("retrieved certificate for requested hash is from unknown identity")
		} else {
			log.Warnf("couldn't get public key for identity %s from local context", id)
			pubKeyBytes, err := v.loadPublicKey(id)
			if err != nil {
				return id, nil, err
			}
			pubKeyPEM, err = v.Protocol.PublicKeyBytesToPEM(pubKeyBytes)
			if err != nil {
				return id, nil, err
			}
		}
	}

	verified, err := v.Protocol.Verify(pubKeyPEM, upp)
	if !verified {
		if err != nil {
			log.Error(err)
		}
		return id, pubKeyPEM, fmt.Errorf("signature of retrieved certificate for requested hash could not be verified")
	}

	return id, pubKeyPEM, nil // todo return bytes
}

// loadPublicKey retrieves the first valid public key associated with an identity from the key service
func (v *Verifier) loadPublicKey(id uuid.UUID) (pubKeyBytes []byte, err error) {
	log.Debugf("requesting public key for identity %s from key service", id.String())

	keys, err := v.Protocol.RequestPublicKeys(id)
	if err != nil {
		return nil, err
	}

	if len(keys) < 1 {
		return nil, fmt.Errorf("no public key for identity %s registered at key service", id.String())
	} else if len(keys) > 1 {
		log.Warnf("several public keys registered for identity %s", id.String())
	}

	log.Printf("retrieved public key for identity %s: %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)

	return base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
}

func getVerificationResponse(respCode int, hash []byte, upp []byte, id uuid.UUID, pkey []byte, errMsg string) h.HTTPResponse {
	verificationResp, err := json.Marshal(verificationResponse{
		Hash:   hash,
		UPP:    upp,
		UUID:   id.String(),
		PubKey: pkey,
		Error:  errMsg,
	})
	if err != nil {
		log.Warnf("error serializing response: %v", err)
	}

	if h.HttpFailed(respCode) {
		log.Errorf("%s", string(verificationResp))
	}

	return h.HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    verificationResp,
	}
}
