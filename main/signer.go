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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const lenRequestID = 16

var (
	env              string
	serviceURL       string
	signedUPPHeader  = []byte{0x95, 0x22}
	chainedUPPHeader = []byte{0x96, 0x23}
)

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	env = conf.Env
	serviceURL = conf.Niomon

	for {
		select {
		case msg := <-msgHandler:
			name := msg.ID.String()

			// buffer last previous signature to be able to reset it in case sending UPP to backend fails
			prevSign, found := p.Signatures[msg.ID]
			if !found {
				prevSign = make([]byte, 64)
			}

			resp, err := handleSigningRequest(p, name, msg.Hash[:], msg.Auth)
			msg.Response <- resp
			if err != nil {
				log.Errorf("%s: %v", name, err)

				// reset previous signature in protocol context to ensure intact chain
				p.Signatures[msg.ID] = prevSign
			} else {
				// persist last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
				if err != nil {
					msg.Response <- errorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist last signature: %v [\"%s\": \"%s\"]",
						err, name, base64.StdEncoding.EncodeToString(p.Signatures[msg.ID]))
				}
			}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}

func handleSigningRequest(p *ExtendedProtocol, name string, hash []byte, auth []byte) (HTTPResponse, error) {
	log.Infof("%s: hash: %s", name, base64.StdEncoding.EncodeToString(hash))

	// send a UPP containing the hash to UBIRCH authentication service
	requestUPP, backendResp, err := anchorHash(p, name, hash, auth)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, ""), err
	}

	// verify validity of the backend response
	responseUPP, err := verifyBackendResponse(p, requestUPP, backendResp)
	if err != nil {
		return errorResponse(http.StatusBadGateway, err.Error()), err
	}

	// get request ID from backend response
	requestID, err := getRequestID(responseUPP)
	if err != nil {
		log.Errorf("could not get request ID from backend response: %v", err)
	} else {
		log.Infof("%s: request ID: %s", name, requestID)
	}

	// check if request was successful
	var httpFailedError error
	if httpFailed(backendResp.Code) {
		httpFailedError = fmt.Errorf("request to UBIRCH Authentication Service failed with response status code: %d", backendResp.Code)
	}

	return extendedResponse(hash, requestUPP, backendResp, requestID), httpFailedError
}

func anchorHash(p *ExtendedProtocol, name string, hash []byte, auth []byte) (ubirch.UPP, HTTPResponse, error) {
	// create a chained UPP
	uppBytes, err := p.SignHash(name, hash, ubirch.Chained)
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not create UBIRCH Protocol Package: %v", err)
	}
	log.Debugf("%s: UPP: %s", name, hex.EncodeToString(uppBytes))

	upp, err := ubirch.Decode(uppBytes)
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not decode created UBIRCH Protocol Package: %v", err)
	}

	// send UPP to ubirch backend
	resp, err := post(serviceURL, uppBytes, niomonHeaders(name, auth))
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("sending request to UBIRCH Authentication Service failed: %v", err)
	}
	log.Debugf("%s: backend response: (%d) %s", name, resp.Code, hex.EncodeToString(resp.Content))

	return upp, resp, nil
}

func niomonHeaders(name string, auth []byte) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": name,
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString(auth),
	}
}

func verifyBackendResponse(p *ExtendedProtocol, requUPP ubirch.UPP, backendResp HTTPResponse) (ubirch.UPP, error) {
	// check if backend response can be a UPP
	if !hasUPPHeaders(backendResp.Content) {
		return nil, fmt.Errorf("invalid backend response: (%d) %q", backendResp.Code, backendResp.Content)
	}

	// verify backend response signature
	if verified, err := p.Verify(env, backendResp.Content); !verified {
		if err != nil {
			log.Errorf("could not verify backend response signature: %v", err)
		}
		return nil, fmt.Errorf("backend response signature verification failed")
	}

	// decode the backend response UPP
	respUPP, err := ubirch.Decode(backendResp.Content)
	if err != nil {
		log.Errorf("decoding backend response failed: %v", err)
		return nil, fmt.Errorf("invalid backend response UPP")
	}

	// verify that backend response previous signature matches signature of request UPP
	if httpSuccess(backendResp.Code) {
		if chainOK, err := ubirch.CheckChainLink(requUPP, respUPP); !chainOK {
			if err != nil {
				log.Errorf("could not verify backend response chain: %v", err)
			}
			return nil, fmt.Errorf("backend response chain check failed")
		}
	}

	return respUPP, nil
}

func hasUPPHeaders(data []byte) bool {
	return bytes.HasPrefix(data, signedUPPHeader) || bytes.HasPrefix(data, chainedUPPHeader)
}

func getRequestID(respUPP ubirch.UPP) (uuid.UUID, error) {
	respPayload := respUPP.GetPayload()
	if len(respPayload) < lenRequestID {
		return uuid.Nil, fmt.Errorf("response payload does not contain request ID: %q", respPayload)
	}
	return uuid.FromBytes(respPayload[:lenRequestID])
}

func errorResponse(code int, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	return HTTPResponse{
		Code:    code,
		Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		Content: []byte(message),
	}
}

func extendedResponse(hash []byte, upp ubirch.UPP, resp HTTPResponse, requestID uuid.UUID) HTTPResponse {
	uppBytes, _ := ubirch.Encode(upp)
	extendedResp, err := json.Marshal(map[string]string{
		"hash":      base64.StdEncoding.EncodeToString(hash),
		"upp":       base64.StdEncoding.EncodeToString(uppBytes),
		"response":  base64.StdEncoding.EncodeToString(resp.Content),
		"requestID": requestID.String(),
	})
	if err != nil {
		log.Warnf("error serializing extended response: %v", err)
	} else {
		resp.Content = extendedResp
		resp.Headers.Del("Content-Length")
		resp.Headers.Set("Content-Type", "application/json")
	}
	return resp
}
