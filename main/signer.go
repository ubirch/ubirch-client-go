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

var (
	env        string
	serviceURL string
)

func handleSigningRequest(p *ExtendedProtocol, name string, hash []byte, auth []byte) (HTTPResponse, error) {
	upp, backendResp, err := anchorHash(p, name, hash, auth)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, ""), err
	}

	err = verifyBackendResponse(p, backendResp.Content, backendResp.Code, upp)
	if err != nil {
		return errorResponse(http.StatusBadGateway, err.Error()), err
	}

	// decode the backend response UPP and get request ID from payload
	respUPP, _ := ubirch.Decode(backendResp.Content)
	requestID, _ := uuid.FromBytes(respUPP.GetPayload()[:16])
	log.Infof("%s: request ID: %s", name, requestID)

	// check if request was successful
	var httpFailedError error
	if httpFailed(backendResp.Code) {
		httpFailedError = fmt.Errorf("request to UBIRCH Authentication Service (%s) failed", serviceURL)
	}

	return extendedResponse(hash, upp, requestID, backendResp), httpFailedError
}

func anchorHash(p *ExtendedProtocol, name string, hash []byte, auth []byte) (upp []byte, backendResp HTTPResponse, err error) {
	// create a chained UPP
	upp, err = p.SignHash(name, hash, ubirch.Chained)
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not create UBIRCH Protocol Package: %v", err)
	}
	log.Debugf("%s: UPP: %s", name, hex.EncodeToString(upp))

	// send UPP to ubirch backend
	respCode, respBody, respHeaders, err := post(serviceURL, upp, niomonHeaders(name, auth))
	if err != nil {
		return nil, HTTPResponse{}, fmt.Errorf("could not send request to UBIRCH Authentication Service: %v", err)
	}
	log.Debugf("%s: backend response: (%d) %s", name, respCode, hex.EncodeToString(respBody))

	return upp, HTTPResponse{
		Code:    respCode,
		Headers: respHeaders,
		Content: respBody,
	}, nil
}

func hasUPPHeaders(data []byte) bool {
	var (
		signedUPPHeader  = []byte{0x95, 0x22}
		chainedUPPHeader = []byte{0x96, 0x23}
	)

	if bytes.HasPrefix(data, signedUPPHeader) || bytes.HasPrefix(data, chainedUPPHeader) {
		return true
	}
	return false
}

func verifyBackendResponse(p *ExtendedProtocol, respBody []byte, respCode int, requUPP []byte) error {
	// check if backend response can be a UPP
	if !hasUPPHeaders(respBody) {
		return fmt.Errorf("invalid backend response: (%d) %q", respCode, respBody)
	}

	// verify backend response signature
	if verified, err := p.Verify(env, respBody); !verified {
		if err != nil {
			log.Errorf("could not verify backend response signature: %v", err)
		}
		return fmt.Errorf("backend response signature verification failed")
	}

	// verify that backend response previous signature matches signature of request UPP
	if httpSuccess(respCode) {
		if chainOK, err := ubirch.CheckChain(requUPP, respBody); !chainOK {
			if err != nil {
				log.Errorf("could not verify backend response chain: %v", err)
			}
			return fmt.Errorf("backend response chain check failed")
		}
	}
	return nil
}

func niomonHeaders(name string, auth []byte) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": name,
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString(auth),
	}
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

func extendedResponse(hash []byte, upp []byte, requestID uuid.UUID, resp HTTPResponse) HTTPResponse {
	extendedResp, err := json.Marshal(map[string]string{
		"hash":      base64.StdEncoding.EncodeToString(hash),
		"upp":       hex.EncodeToString(upp),
		"requestID": requestID.String(),
		"response":  hex.EncodeToString(resp.Content),
	})
	if err != nil {
		log.Warnf("error serializing extended response: %v", err)
	} else {
		resp.Content = extendedResp
		resp.Headers.Del("Content-Length")
		resp.Headers.Set("Content-Type", "application/json")
	}
	return resp // todo log extended response
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	env = conf.Env
	serviceURL = conf.Niomon

	for {
		select {
		case msg := <-msgHandler:
			name := msg.ID.String()

			log.Printf("%s: hash: %s", name, base64.StdEncoding.EncodeToString(msg.Hash[:]))

			// buffer last signature in case sending UPP to backend fails
			prevSign, found := p.Signatures[msg.ID]
			if !found {
				prevSign = make([]byte, 64)
			}

			resp, err := handleSigningRequest(p, name, msg.Hash[:], msg.Auth)
			if err != nil {
				log.Errorf("%s: %v", name, err)

				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				p.Signatures[msg.ID] = prevSign
			} else {
				// persist last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
				if err != nil {
					msg.Response <- errorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist last signature for UUID %s: %v", name, err)
				}
			}
			msg.Response <- resp

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}
