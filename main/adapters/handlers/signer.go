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
	Hash                      []byte          `json:"hash"`
	Operation                 string          `json:"operation"`
	UPP                       []byte          `json:"upp"`
	PublicKey                 []byte          `json:"publicKey"`
	Response                  *h.HTTPResponse `json:"response,omitempty"`
	RequestID                 string          `json:"requestID,omitempty"`
	ResponseSignatureVerified bool            `json:"responseSignatureVerified"`
	ResponseChainVerified     bool            `json:"responseChainVerified"`
}

type SignerProtocol interface {
	LoadActiveFlag(uuid.UUID) (bool, error)
	StartTransaction(context.Context) (repository.TransactionCtx, error)
	LoadSignatureForUpdate(repository.TransactionCtx, uuid.UUID) ([]byte, error)
	StoreSignature(repository.TransactionCtx, uuid.UUID, []byte) error
	GetPublicKeyBytes(uuid.UUID) ([]byte, error)
	SignatureLength() int
	Sign(ubirch.UPP) ([]byte, error)
}

type ResponseVerifier interface {
	VerifyBackendResponse(requestUPP, responseUPP []byte) (signatureOk bool, chainOk bool, err error)
}

type Signer struct {
	SignerProtocol
	ResponseVerifier
	SendToAuthService func(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error)
}

func (s *Signer) Sign(msg h.HTTPRequest) h.HTTPResponse {
	log.Infof("create UPP: uuid: %s, hash: %s, operation: %s, offline: %v",
		msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]), msg.Operation, msg.Offline)

	active, err := s.SignerProtocol.LoadActiveFlag(msg.ID)
	if err != nil {
		log.Errorf("%s: could not load active flag: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	if !active {
		log.Warnf("%s: key deactivated", msg.ID)
		return errorResponse(http.StatusBadRequest, "key deactivated")
	}

	var tx repository.TransactionCtx
	var prevSignature, uppBytes []byte

	if msg.Operation == h.ChainHash {
		tx, err = s.SignerProtocol.StartTransaction(msg.Ctx)
		if err != nil {
			log.Errorf("%s: initializing transaction failed: %v", msg.ID, err)
			return errorResponse(http.StatusServiceUnavailable, "")
		}

		prevSignature, err = s.SignerProtocol.LoadSignatureForUpdate(tx, msg.ID)
		if err != nil {
			log.Errorf("%s: could not load signature: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}

		uppBytes, err = s.getChainedUPP(msg.ID, msg.Hash, prevSignature)
		if err != nil {
			log.Errorf("%s: could not create chained UPP: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}
		log.Debugf("%s: chained UPP: %x", msg.ID, uppBytes)
	} else {
		uppBytes, err = s.getSignedUPP(msg.ID, msg.Hash, msg.Operation)
		if err != nil {
			log.Errorf("%s: could not create signed UPP: %v", msg.ID, err)
			return errorResponse(http.StatusInternalServerError, "")
		}
		log.Debugf("%s: signed UPP: %x", msg.ID, uppBytes)
	}

	pub, err := s.SignerProtocol.GetPublicKeyBytes(msg.ID)
	if err != nil {
		log.Warnf("%s: could not get public key: %v", msg.ID, err)
	}

	signingResp := &signingResponse{
		Hash:                      msg.Hash[:],
		Operation:                 string(msg.Operation),
		UPP:                       uppBytes,
		PublicKey:                 pub,
		Response:                  nil,
		RequestID:                 "",
		ResponseSignatureVerified: false,
		ResponseChainVerified:     false,
	}

	var resp h.HTTPResponse
	if msg.Offline {
		resp = getHTTPResponse(http.StatusOK, signingResp)
	} else {
		resp = s.sendUPP(msg, uppBytes, signingResp)
	}

	// persist last signature only if UPP was successfully received by ubirch backend
	if msg.Operation == h.ChainHash && h.HttpSuccess(resp.StatusCode) {
		signature := uppBytes[len(uppBytes)-s.SignerProtocol.SignatureLength():]

		err = s.SignerProtocol.StoreSignature(tx, msg.ID, signature)
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

func (s *Signer) getChainedUPP(id uuid.UUID, hash [32]byte, prevSignature []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prom.SignatureCreationDuration)
	defer timer.ObserveDuration()

	return s.SignerProtocol.Sign(
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

	timer := prometheus.NewTimer(prom.SignatureCreationDuration)
	defer timer.ObserveDuration()

	return s.SignerProtocol.Sign(
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    id,
			Hint:    hint,
			Payload: hash[:],
		})
}

func (s *Signer) sendUPP(msg h.HTTPRequest, upp []byte, signingResp *signingResponse) h.HTTPResponse {
	// send UPP to ubirch backend
	backendResp, err := s.SendToAuthService(msg.ID, msg.Auth, upp)
	if err != nil {
		if os.IsTimeout(err) {
			log.Errorf("%s: request to UBIRCH Trust Service timed out: %v", msg.ID, err)
			return errorResponse(http.StatusGatewayTimeout, "")
		} else {
			log.Errorf("%s: sending request to UBIRCH Trust Service failed: %v", msg.ID, err)
			return errorResponse(http.StatusBadGateway, "")
		}
	}
	log.Debugf("%s: backend response: (%d) %x", msg.ID, backendResp.StatusCode, backendResp.Content)

	signingResp.Response = &backendResp

	// verify validity of the backend response UPP
	signingResp.ResponseSignatureVerified, signingResp.ResponseChainVerified, err = s.VerifyBackendResponse(upp, backendResp.Content)
	if err != nil {
		resp := getHTTPResponse(http.StatusBadGateway, signingResp)
		log.Errorf("%s: unverifiable response from UBIRCH Trust Service (niomon): %v, request: %s",
			msg.ID, err, string(resp.Content))
		return resp
	}

	// decode the backend response UPP and get request ID
	responseUPPStruct, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Warnf("decoding backend response failed: %v, backend response: (%d) %q",
			err, backendResp.StatusCode, backendResp.Content)
	} else {
		signingResp.RequestID, err = getRequestID(responseUPPStruct)
		if err != nil {
			log.Warnf("could not get request ID from backend response: %v", err)
		} else {
			log.Infof("%s: request ID: %s", msg.ID, signingResp.RequestID)
		}
	}

	resp := getHTTPResponse(backendResp.StatusCode, signingResp)

	if h.HttpFailed(backendResp.StatusCode) {
		log.Errorf("%s: request to UBIRCH Trust Service (niomon) failed: (%d) %s",
			msg.ID, backendResp.StatusCode, string(resp.Content))
	}

	return resp
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
		Content:    []byte(message + "\n"),
	}
}

func getHTTPResponse(statusCode int, signingResp *signingResponse) h.HTTPResponse {
	respContent, err := json.Marshal(signingResp)
	if err != nil {
		log.Warnf("error serializing signing response: %v", err)
	}

	headers := http.Header{"Content-Type": {h.JSONType}}
	if signingResp.Response != nil && statusCode != http.StatusOK {
		errValues := signingResp.Response.Header.Values(h.XErrorHeader)
		for _, value := range errValues {
			headers.Add(h.XErrorHeader, value)
		}
	}

	return h.HTTPResponse{
		StatusCode: statusCode,
		Header:     headers,
		Content:    respContent,
	}
}
