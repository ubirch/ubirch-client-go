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
	"encoding/base64"
	"encoding/json"
	"fmt"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/logger"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type operation string

const (
	anchorHash  operation = "anchor"
	disableHash operation = "disable"
	enableHash  operation = "enable"
	deleteHash  operation = "delete"

	lenRequestID = 16
)

var hintLookup = map[operation]ubirch.Hint{
	anchorHash:  ubirch.Binary,
	disableHash: ubirch.Disable,
	enableHash:  ubirch.Enable,
	deleteHash:  ubirch.Delete,
}

type signingResponse struct {
	Error     string         `json:"error,omitempty"`
	Hash      []byte         `json:"hash,omitempty"`
	UPP       []byte         `json:"upp,omitempty"`
	Response  h.HTTPResponse `json:"response,omitempty"`
	RequestID string         `json:"requestID,omitempty"`
}

type Signer struct {
	Protocol             *repository.ExtendedProtocol
	AuthTokensBuffer     map[uuid.UUID]string
	AuthTokenBufferMutex *sync.RWMutex
}

func (s *Signer) checkExists(uid uuid.UUID) (bool, error) {
	s.AuthTokenBufferMutex.RLock()
	_, found := s.AuthTokensBuffer[uid]
	s.AuthTokenBufferMutex.RUnlock()

	if !found {
		return s.Protocol.Exists(uid)
	}
	return true, nil
}

func (s *Signer) getAuth(uid uuid.UUID) (auth string, err error) {
	var found bool

	s.AuthTokenBufferMutex.RLock()
	auth, found = s.AuthTokensBuffer[uid]
	s.AuthTokenBufferMutex.RUnlock()

	if !found {
		auth, err = s.Protocol.GetAuthToken(uid)
		if err != nil {
			return "", err
		}

		s.AuthTokenBufferMutex.Lock()
		s.AuthTokensBuffer[uid] = auth
		s.AuthTokenBufferMutex.Unlock()
	}
	return auth, nil
}

// handle incoming messages, create, sign and send a chained ubirch protocol packet (UPP) to the ubirch backend
func (s *Signer) chain(tx interface{}, msg HTTPRequest) h.HTTPResponse {
	log.Infof("%s: anchor hash [chained]: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	identity, err := s.Protocol.FetchIdentity(tx, msg.ID)
	if err != nil {
		log.Errorf("%s: could not fetch identity: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	uppBytes, err := s.getChainedUPP(msg.ID, msg.Hash, identity.PrivateKey, identity.Signature)
	if err != nil {
		log.Errorf("%s: could not create chained UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: chained UPP: %x", msg.ID, uppBytes)

	resp := s.sendUPP(msg, uppBytes)

	// persist last signature only if UPP was successfully received by ubirch backend
	if h.HttpSuccess(resp.StatusCode) {
		signature := uppBytes[len(uppBytes)-s.Protocol.SignatureLength():]

		err = s.Protocol.SetSignature(tx, msg.ID, signature)
		if err != nil {
			log.Errorf("unable to persist last signature: %v [\"%s\": \"%s\"]",
				err, msg.ID, base64.StdEncoding.EncodeToString(signature))
			return errorResponse(http.StatusInternalServerError, "")
		}

		err = s.Protocol.CloseTransaction(tx, repository.Commit)
		if err != nil {
			log.Errorf("%s: committing transaction failed: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}

		logger.AuditLog(fmt.Sprintf("created chained UPP for identity %s with hash %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:])))
	}

	return resp
}

func (s *Signer) Sign(msg HTTPRequest, op operation) h.HTTPResponse {
	log.Infof("%s: %s hash: %s", msg.ID, op, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	privateKeyPEM, err := s.Protocol.GetPrivateKey(msg.ID)
	if err != nil {
		log.Errorf("%s: could not fetch private Key for UUID: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	uppBytes, err := s.getSignedUPP(msg.ID, msg.Hash, privateKeyPEM, op)
	if err != nil {
		log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)

	resp := s.sendUPP(msg, uppBytes)

	if h.HttpSuccess(resp.StatusCode) {
		logger.AuditLog(fmt.Sprintf("created signed UPP [%s] for identity %s with hash %s", op, msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:])))
	}

	return resp
}

func (s *Signer) getChainedUPP(id uuid.UUID, hash [32]byte, privateKeyPEM, prevSignature []byte) ([]byte, error) {
	return s.Protocol.Sign(
		privateKeyPEM,
		&ubirch.ChainedUPP{
			Version:       ubirch.Chained,
			Uuid:          id,
			PrevSignature: prevSignature,
			Hint:          ubirch.Binary,
			Payload:       hash[:],
		})
}

func (s *Signer) getSignedUPP(id uuid.UUID, hash [32]byte, privateKeyPEM []byte, op operation) ([]byte, error) {
	hint, found := hintLookup[op]
	if !found {
		return nil, fmt.Errorf("%s: invalid operation: \"%s\"", id, op)
	}

	return s.Protocol.Sign(
		privateKeyPEM,
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) sendUPP(msg HTTPRequest, upp []byte) h.HTTPResponse {
	// send UPP to ubirch backend
	backendResp, err := s.Protocol.SendToAuthService(msg.ID, msg.Auth, upp)
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

	return getSigningResponse(backendResp.StatusCode, msg, upp, backendResp, requestID, "")
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

func getSigningResponse(respCode int, msg HTTPRequest, upp []byte, backendResp h.HTTPResponse, requestID string, errMsg string) h.HTTPResponse {
	signingResp, err := json.Marshal(signingResponse{
		Hash:      msg.Hash[:],
		UPP:       upp,
		Response:  backendResp,
		RequestID: requestID,
		Error:     errMsg,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	if h.HttpFailed(respCode) {
		log.Errorf("%s: request failed: (%d) %s", msg.ID, respCode, string(signingResp))
	}

	return h.HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
