// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

const (
	lenRequestID = 16
)

var hintLookup = map[h.Operation]ubirch.Hint{
	h.AnchorHash:  ubirch.Binary,
	h.DisableHash: ubirch.Disable,
	h.EnableHash:  ubirch.Enable,
	h.DeleteHash:  ubirch.Delete,
}

type signingResponse struct {
	Error     string         `json:"error,omitempty"`
	Hash      []byte         `json:"hash"`
	UPP       []byte         `json:"upp"`
	PublicKey []byte         `json:"publicKey"`
	Response  h.HTTPResponse `json:"response"`
	RequestID string         `json:"requestID"`
}

type Signer struct {
	Protocol          *repository.ExtendedProtocol
	SendToAuthService func(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error)
}

// handle incoming messages, create, sign and send a chained ubirch protocol packet (UPP) to the ubirch backend
func (s *Signer) Chain(msg h.HTTPRequest, ctx context.Context) h.HTTPResponse {
	log.Infof("%s: anchor hash [chained]: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	active, err := s.Protocol.LoadActiveFlag(msg.ID)
	if err != nil {
		log.Errorf("%s: could not load active flag: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	if !active {
		log.Warnf("%s: key deactivated", msg.ID)
		return errorResponse(http.StatusBadRequest, "key deactivated")
	}

	tx, err := s.Protocol.StartTransaction(ctx)
	if err != nil {
		log.Errorf("%s: initializing transaction failed: %v", msg.ID, err)
		return errorResponse(http.StatusServiceUnavailable, "")
	}

	prevSignature, err := s.Protocol.LoadSignatureForUpdate(tx, msg.ID)
	if err != nil {
		log.Errorf("%s: could not load signature: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	timer := prometheus.NewTimer(prom.SignatureCreationDuration)
	uppBytes, err := s.getChainedUPP(msg.ID, msg.Hash, prevSignature)
	timer.ObserveDuration()
	if err != nil {
		log.Errorf("%s: could not create chained UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: chained UPP: %x", msg.ID, uppBytes)

	resp := s.sendUPP(msg, uppBytes)

	// persist last signature only if UPP was successfully received by ubirch backend
	if h.HttpSuccess(resp.StatusCode) {
		signature := uppBytes[len(uppBytes)-s.Protocol.SignatureLength():]

		err = s.Protocol.StoreSignature(tx, msg.ID, signature)
		if err != nil {
			// this usually happens, if the request context was cancelled because the client already left (timeout or cancel)
			log.Errorf("%s: storing signature failed: %v", msg.ID, err)
			log.Warnf("%s: request has been processed, but response could not be sent: (%d) %s",
				msg.ID, resp.StatusCode, string(resp.Content))
			return errorResponse(http.StatusInternalServerError, "")
		}

		prom.SignatureCreationCounter.Inc()
	}

	return resp
}

func (s *Signer) Sign(msg h.HTTPRequest, op h.Operation) h.HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, op, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	active, err := s.Protocol.LoadActiveFlag(msg.ID)
	if err != nil {
		log.Errorf("%s: could not load active flag: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	if !active {
		log.Warnf("%s: key deactivated", msg.ID)
		return errorResponse(http.StatusBadRequest, "key deactivated")
	}

	uppBytes, err := s.getSignedUPP(msg.ID, msg.Hash, op)
	if err != nil {
		log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)

	return s.sendUPP(msg, uppBytes)
}

func (s *Signer) getChainedUPP(id uuid.UUID, hash [32]byte, prevSignature []byte) ([]byte, error) {
	return s.Protocol.Sign(
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          id,
			PrevSignature: prevSignature,
			Hint:          ubirch.Binary,
			Payload:       hash[:],
		})
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash [32]byte, op h.Operation) ([]byte, error) {
	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.Protocol.Sign(
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) sendUPP(msg h.HTTPRequest, upp []byte) h.HTTPResponse {
	// send UPP to ubirch backend
	timer := prometheus.NewTimer(prom.UpstreamResponseDuration)
	backendResp, err := s.SendToAuthService(msg.ID, msg.Auth, upp)
	timer.ObserveDuration()
	if err != nil {
		if os.IsTimeout(err) {
			log.Errorf("%s: request to UBIRCH Authentication Service timed out after %s: %v", msg.ID, h.BackendRequestTimeout.String(), err)
			return errorResponse(http.StatusGatewayTimeout, "")
		} else {
			log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}
	}
	log.Debugf("%s: backend response: (%d) %x", msg.ID, backendResp.StatusCode, backendResp.Content)

	// decode the backend response UPP and get request ID
	var requestID string
	responseUPPStruct, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Warnf("decoding backend response failed: %v, backend response: (%d) %q",
			err, backendResp.StatusCode, backendResp.Content)
	} else {
		requestID, err = getRequestID(responseUPPStruct)
		if err != nil {
			log.Warnf("could not get request ID from backend response: %v", err)
		} else {
			log.Infof("%s: request ID: %s", msg.ID, requestID)
		}
	}

	pub, err := s.Protocol.GetPublicKeyBytes(msg.ID)
	if err != nil {
		log.Warnf("%s: could not get public key: %v", msg.ID, err)
	}

	return getSigningResponse(msg, upp, pub, backendResp, requestID)
}

func getRequestID(respUPP ubirch.UPP) (string, error) {
	respPayload := respUPP.GetPayload()
	if len(respPayload) < lenRequestID {
		return "n/a", fmt.Errorf("response payload does not contain request ID: %q", respPayload)
	}
	requestID, err := uuid.FromBytes(respPayload[:lenRequestID])
	if err != nil {
		return "n/a", err
	}
	return requestID.String(), nil
}

func errorResponse(code int, message string) h.HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	return h.HTTPResponse{
		StatusCode: code,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

func getSigningResponse(msg h.HTTPRequest, upp []byte, pub []byte, backendResp h.HTTPResponse, requestID string) h.HTTPResponse {
	signingResp, err := json.Marshal(signingResponse{
		Hash:      msg.Hash[:],
		UPP:       upp,
		PublicKey: pub,
		Response:  backendResp,
		RequestID: requestID,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	if h.HttpFailed(backendResp.StatusCode) {
		log.Errorf("%s: request to ubirch authentication service (niomon) failed: (%d) %s", msg.ID, backendResp.StatusCode, string(signingResp))
	}

	return h.HTTPResponse{
		StatusCode: backendResp.StatusCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
