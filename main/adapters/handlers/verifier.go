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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
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
	RequestHash                   func(hashBase64 string) (h.HTTPResponse, error)
	RequestPublicKeys             func(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error)
	VerifyFromKnownIdentitiesOnly bool
	VerificationTimeout           time.Duration
}

func (v *Verifier) Verify(ctx context.Context, hash []byte) h.HTTPResponse {
	log.Infof("verifying hash %s", base64.StdEncoding.EncodeToString(hash))

	// retrieve certificate for hash from the ubirch backend
	code, upp, err := v.loadUPP(ctx, hash)
	if err != nil {
		log.Error(err)
		return errorResponse(code, err.Error())
	}
	log.Debugf("retrieved UPP %x", upp)

	// verify validity of the retrieved UPP locally
	id, pkey, err := v.verifyUppSignature(upp, v.VerifyFromKnownIdentitiesOnly)
	if err != nil {
		return getVerificationResponse(http.StatusForbidden, hash, upp, id, pkey, err.Error())
	}
	log.Debugf("verified UPP from identity %s using public key %s", id, base64.StdEncoding.EncodeToString(pkey))

	return getVerificationResponse(http.StatusOK, hash, upp, id, pkey, "")
}

func (v *Verifier) VerifyOffline(upp, hash []byte) h.HTTPResponse {
	log.Infof("performing offline verification for UPP %s and hash %s", base64.StdEncoding.EncodeToString(upp), base64.StdEncoding.EncodeToString(hash))

	// verify validity of the UPP locally
	id, pkey, err := v.verifyUppSignature(upp, true)
	if err != nil {
		return getVerificationResponse(http.StatusForbidden, nil, upp, id, pkey, err.Error())
	}
	log.Debugf("verified UPP from identity %s using public key %s", id, base64.StdEncoding.EncodeToString(pkey))

	// verify data hash matches UPP payload
	err = v.verifyDataMatch(upp, hash)
	if err != nil {
		log.Error(err)
		return errorResponse(http.StatusBadRequest, err.Error())
	}
	log.Debugf("verified data hash %s", base64.StdEncoding.EncodeToString(hash))

	return getVerificationResponse(http.StatusOK, hash, upp, id, pkey, "")
}

// loadUPP retrieves the UPP which contains a given hash from the ubirch backend
func (v *Verifier) loadUPP(ctx context.Context, hash []byte) (int, []byte, error) {
	var resp h.HTTPResponse
	var err error
	hashBase64 := base64.StdEncoding.EncodeToString(hash)

	n := 0
	for stay, timeout := true, time.After(v.VerificationTimeout); stay; {
		n++
		select {
		case <-ctx.Done():
			stay = false
		case <-timeout:
			stay = false
		default:
			resp, err = v.RequestHash(hashBase64)
			if err != nil {
				if os.IsTimeout(err) {
					return http.StatusGatewayTimeout, nil, fmt.Errorf("request to UBIRCH Verification Service timed out: %v", err)
				} else {
					return http.StatusBadGateway, nil, fmt.Errorf("sending request to UBIRCH Verification Service failed: %v", err)
				}
			}
			stay = resp.StatusCode == http.StatusNotFound
			if stay {
				log.Debugf("Couldn't verify hash yet (%d). Retry... %d", resp.StatusCode, n)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	if h.HttpFailed(resp.StatusCode) {
		return resp.StatusCode, nil, fmt.Errorf("could not retrieve certificate for hash %s from UBIRCH verification service: - %d - %q", hashBase64, resp.StatusCode, resp.Content)
	}

	vf := verification{}
	err = json.NewDecoder(bytes.NewBuffer(resp.Content)).Decode(&vf)
	if err != nil {
		return http.StatusBadGateway, nil, fmt.Errorf("unable to decode verification response: %v", err)
	}
	return http.StatusOK, vf.UPP, nil
}

// verifyUppSignature verifies the signature of UPPs from known identities using
// their public key from the local keystore.
// If the public key can not be found in the local keystore, i.e. the identity
// is unknown, the public key will be requested from the UBIRCH identity service
// only if verifyFromKnownIdentitiesOnly is `false`.
func (v *Verifier) verifyUppSignature(upp []byte, verifyFromKnownIdentitiesOnly bool) (uuid.UUID, []byte, error) {
	uppStruct, err := ubirch.Decode(upp)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("retrieved invalid UPP: %v", err)
	}

	id := uppStruct.GetUuid()

	pubKeyPEM, err := v.Protocol.LoadPublicKey(id)
	if err != nil {
		if err == repository.ErrNotExist {
			if verifyFromKnownIdentitiesOnly {
				return id, nil, fmt.Errorf("UPP from unknown identity")
			}

			log.Warnf("UPP from unknown identity %s", id)
			err := v.loadPublicKey(id)
			if err != nil {
				return id, nil, err
			}
			pubKeyPEM, err = v.Protocol.LoadPublicKey(id)
			if err != nil {
				return id, nil, err
			}

		} else {
			return id, nil, err
		}
	}

	verified, err := v.Protocol.Verify(id, upp)
	if !verified {
		if err != nil {
			log.Error(err)
		}
		return id, pubKeyPEM, fmt.Errorf("signature of retrieved certificate for requested hash could not be verified")
	}

	return id, pubKeyPEM, nil // todo return bytes
}

// loadPublicKey retrieves the first valid public key associated with an identity from the key service
func (v *Verifier) loadPublicKey(id uuid.UUID) error {
	log.Infof("requesting public key for identity %s from identity service", id)

	keys, err := v.RequestPublicKeys(id)
	if err != nil {
		return err
	}

	if len(keys) < 1 {
		return fmt.Errorf("no public key for identity %s registered at key service", id.String())
	} else if len(keys) > 1 {
		log.Warnf("several public keys registered for identity %s", id.String())
	}

	log.Infof("retrieved public key for identity %s: %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)

	pubKeyBytes, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		return err
	}

	return v.Protocol.SetPublicKeyBytes(id, pubKeyBytes)
}

func (v *Verifier) verifyDataMatch(upp, hash []byte) error {
	uppStruct, err := ubirch.Decode(upp)
	if err != nil {
		return fmt.Errorf("invalid UPP: %v", err)
	}

	if !bytes.Equal(uppStruct.GetPayload(), hash) {
		return fmt.Errorf("data does not match UPP payload, data hash: %s, UPP payload: %s",
			base64.StdEncoding.EncodeToString(hash),
			base64.StdEncoding.EncodeToString(uppStruct.GetPayload()),
		)
	}

	return nil
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
