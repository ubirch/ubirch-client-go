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

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"

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

type signingResponse struct {
	Error     string       `json:"error,omitempty"`
	Operation operation    `json:"operation,omitempty"`
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type Signer struct {
	protocol       *ExtendedProtocol
	env            string
	authServiceURL string
	MessageHandler chan HTTPRequest
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func (s *Signer) chainer() error {
	for msg := range s.MessageHandler {
		// buffer last previous signature to be able to reset it in case sending UPP to backend fails
		prevSign, found := s.protocol.Signatures[msg.ID]
		if !found {
			prevSign = make([]byte, 64)
		}

		resp := s.handleSigningRequest(msg)
		msg.Response <- resp
		if httpFailed(resp.StatusCode) {
			// reset previous signature in protocol context to ensure intact chain
			s.protocol.Signatures[msg.ID] = prevSign
		} else {
			// persist last signature after UPP was successfully received in ubirch backend
			err := s.protocol.PersistContext()
			if err != nil {
				return fmt.Errorf("unable to persist last signature: %v [\"%s\": \"%s\"]",
					err, msg.ID.String(), base64.StdEncoding.EncodeToString(s.protocol.Signatures[msg.ID]))
			}
		}
	}

	log.Debug("shutting down signer")
	return nil
}

func (s *Signer) handleSigningRequest(msg HTTPRequest) HTTPResponse {
	name := msg.ID.String()
	hash := msg.Hash[:]
	auth := msg.Auth

	// create and sign a UPP containing the hash
	var upp []byte
	var err error

	switch msg.Operation {
	case anchorHash:
		upp, err = s.anchorHash(name, hash)
	case disableHash:
		upp, err = s.disableHash(name, hash)
	case enableHash:
		upp, err = s.enableHash(name, hash)
	case deleteHash:
		upp, err = s.deleteHash(name, hash)
	default:
		err = fmt.Errorf("unsupported operation: \"%s\"", msg.Operation)
	}

	if err != nil {
		log.Errorf("%s: could not create UBIRCH Protocol Package: %v", name, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: UPP: %s", name, hex.EncodeToString(upp))

	// send UPP to ubirch backend
	backendResp, err := post(s.authServiceURL, upp, ubirchHeader(msg.ID, auth))
	if err != nil {
		log.Errorf("%s: sending request to UBIRCH Authentication Service failed: %v", name, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: backend response: (%d) %s", name, backendResp.StatusCode, hex.EncodeToString(backendResp.Content))

	// decode the backend response UPP and get request ID
	var requestID string
	responseUPPStruct, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Warnf("decoding backend response failed: %v, backend response: (%d) %q", err, backendResp.StatusCode, backendResp.Content)
	} else {
		requestID, err = getRequestID(responseUPPStruct)
		if err != nil {
			log.Warnf("could not get request ID from backend response: %v", err)
		} else {
			log.Infof("%s: request ID: %s", name, requestID)
		}
	}

	return getSigningResponse(backendResp.StatusCode, msg, upp, backendResp, requestID, "")
}

func (s *Signer) anchorHash(name string, hash []byte) ([]byte, error) {
	log.Infof("%s: anchoring hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	return s.protocol.SignHash(name, hash, ubirch.Chained)
}

func (s *Signer) disableHash(name string, hash []byte) ([]byte, error) {
	log.Infof("%s: disabling hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	return s.protocol.SignHashExtended(name, hash, ubirch.Signed, ubirch.Disable)
}

func (s *Signer) enableHash(name string, hash []byte) ([]byte, error) {
	log.Infof("%s: enabling hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	return s.protocol.SignHashExtended(name, hash, ubirch.Signed, ubirch.Enable)
}

func (s *Signer) deleteHash(name string, hash []byte) ([]byte, error) {
	log.Infof("%s: deleting hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	return s.protocol.SignHashExtended(name, hash, ubirch.Signed, ubirch.Delete)
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

func errorResponse(code int, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	log.Error(message)
	return HTTPResponse{
		StatusCode: code,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Content:    []byte(message),
	}
}

func getSigningResponse(respCode int, msg HTTPRequest, upp []byte, backendResp HTTPResponse, requestID string, errMsg string) HTTPResponse {
	signingResp, err := json.Marshal(signingResponse{
		Hash:      msg.Hash[:],
		UPP:       upp,
		Response:  backendResp,
		RequestID: requestID,
		Operation: msg.Operation,
		Error:     errMsg,
	})
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	if httpFailed(respCode) {
		log.Errorf("%s: %s", msg.ID, string(signingResp))
	}

	return HTTPResponse{
		StatusCode: respCode,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Content:    signingResp,
	}
}
