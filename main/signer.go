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

func niomonHeaders(name string, auth []byte) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": name,
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString(auth),
	}
}

func anchorHash(p *ExtendedProtocol, name string, hash []byte, auth []byte, conf Config) (HTTPResponse, error) {
	// create a chained UPP
	upp, err := p.SignHash(name, hash, ubirch.Chained)
	if err != nil {
		errMsg := fmt.Sprintf("could not create UBIRCH Protocol Package: %v", err)
		return HTTPErrorResponse(http.StatusInternalServerError, ""), fmt.Errorf(errMsg)
	}
	log.Debugf("%s: UPP: %s", name, hex.EncodeToString(upp))

	// send UPP to ubirch backend
	respCode, respBody, respHeaders, err := post(conf.Niomon, upp, niomonHeaders(name, auth))
	if err != nil {
		errMsg := fmt.Sprintf("could not send request to UBIRCH Authentication Service: %v", err)
		return HTTPErrorResponse(http.StatusInternalServerError, ""), fmt.Errorf(errMsg)
	}
	log.Debugf("%s: backend response: (%d) %s", name, respCode, hex.EncodeToString(respBody))

	// verify backend response signature
	verified, err := p.Verify(conf.Env, respBody)
	if err != nil {
		errMsg := fmt.Sprintf("could not verify backend response signature: %v\n"+
			" backend response: (%d) %q", err, respCode, respBody)
		return HTTPErrorResponse(http.StatusInternalServerError, ""), fmt.Errorf(errMsg)
	} else if !verified {
		errMsg := fmt.Sprintf("backend response signature verification failed\n"+
			" backend response: (%d) %s", respCode, hex.EncodeToString(respBody))
		return HTTPErrorResponse(http.StatusBadGateway, errMsg), fmt.Errorf(errMsg)
	}
	log.Debugf("%s: backend response signature verified", name)

	// decode the backend response
	respUPP, err := ubirch.Decode(respBody)
	if err != nil {
		errMsg := fmt.Sprintf("could not decode backend response: %v\n"+
			" backend response: (%d) %q", err, respCode, respBody)
		return HTTPErrorResponse(http.StatusBadGateway, errMsg), fmt.Errorf(errMsg)
	}

	// verify that backend response previous signature matches signature of request UPP
	if respUPP.GetVersion() == ubirch.Chained {
		chainOK, err := ubirch.CheckChain(upp, respBody)
		if !chainOK {
			if err != nil {
				log.Errorf("could not verify backend response chain: %v", err)
			}
			errMsg := fmt.Sprintf("backend response chain check failed\n"+
				" backend response: (%d) %s", respCode, hex.EncodeToString(respBody))
			return HTTPErrorResponse(http.StatusBadGateway, errMsg), fmt.Errorf(errMsg)
		}
		log.Debugf("%s: backend response chain verified", name)
	}

	// get request ID from backend response payload
	requestID, err := uuid.FromBytes(respUPP.GetPayload()[:16])
	if err != nil {
		log.Warnf("%s: unable to get request ID from backend response payload: %v\n"+
			" backend response payload: %q", name, err, respUPP.GetPayload())
	} else {
		log.Infof("%s: request ID: %s", name, requestID)
	}

	// check if request was successful
	var httpFailedError error
	if httpFailed(respCode) {
		httpFailedError = fmt.Errorf("request to UBIRCH Authentication Service (%s) failed\n"+
			" backend response: (%d) %s", conf.Niomon, respCode, hex.EncodeToString(respBody))
	}

	response, err := json.Marshal(map[string][]byte{
		"hash":      hash,
		"upp":       upp,
		"requestID": requestID[:],
		"response":  respBody,
	})
	if err != nil {
		log.Warnf("error serializing extended response: %v", err)
		response = respBody
	} else {
		respHeaders.Del("Content-Length")
		respHeaders.Set("Content-Type", "application/json")
	}

	return HTTPResponse{Code: respCode, Headers: respHeaders, Content: response}, httpFailedError
}

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:
			name := msg.ID.String()

			log.Printf("%s: signing hash: %s", name, base64.StdEncoding.EncodeToString(msg.Hash[:]))

			resp, err := anchorHash(p, name, msg.Hash[:], msg.Auth, conf)
			if err != nil {
				log.Errorf("%s: %v", name, err)

				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to load last signature for UUID %s: %v", name, err)
				}
			} else {
				log.Debugf("%s: UPP successfully sent to %s", name, conf.Niomon)

				// persist last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
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
