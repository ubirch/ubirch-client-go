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

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// create a chained UPP
			log.Printf("%s: signing hash: %s", name, base64.StdEncoding.EncodeToString(msg.Hash[:]))

			upp, err := p.SignHash(name, msg.Hash[:], ubirch.Chained)
			if err != nil {
				msg.Response <- HTTPErrorResponse(
					http.StatusInternalServerError,
					fmt.Sprintf("error creating UPP for UUID %s: %v", name, err),
				)
				continue // todo persist or discard signature?
			}
			log.Debugf("%s: UPP: %s", name, hex.EncodeToString(upp))

			// send UPP to ubirch backend
			respCode, respBody, respHeaders, err := post(conf.Niomon, upp, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString(msg.Auth),
			})
			if err != nil {
				msg.Response <- HTTPErrorResponse(
					http.StatusInternalServerError,
					fmt.Sprintf("unable to send request to UBIRCH Authentication Service: %v", err),
				)
				continue // todo persist or discard signature?
			}
			log.Debugf("%s: response: (%d) %s", name, respCode, hex.EncodeToString(respBody))

			// verify backend response signature
			verified, err := p.Verify(conf.Env, respBody)
			if err != nil {
				msg.Response <- HTTPErrorResponse(
					http.StatusBadGateway,
					fmt.Sprintf("%s: backend response signature could not be verified: %v\n"+
						" backend response was: (%d) %s", name, err, respCode, hex.EncodeToString(respBody)),
				)
				continue // todo persist or discard signature?
			} else if !verified {
				msg.Response <- HTTPErrorResponse(
					http.StatusBadGateway,
					fmt.Sprintf("%s: backend response signature verification failed\n"+
						" backend response was: (%d) %s", name, respCode, hex.EncodeToString(respBody)),
				)
				continue // todo persist or discard signature?
			}
			log.Debugf("%s: backend response signature verified", name)

			// decode the backend response
			var isRespDecodable bool
			var isRespChainedUPP bool
			var requestID uuid.UUID

			respUPP, err := ubirch.Decode(respBody)
			if err != nil {
				log.Warnf("%s: unable to decode backend response: %v\n backend response was: (%d) %s",
					name, err, respCode, hex.EncodeToString(respBody))
			} else {
				isRespDecodable = true
				isRespChainedUPP = respUPP.GetVersion() == ubirch.Chained

				// verify that backend response previous signature matches signature of request UPP
				if isRespChainedUPP {
					if !bytes.Equal(p.Signatures[uid], respUPP.GetPrevSignature()) {
						msg.Response <- HTTPErrorResponse(
							http.StatusBadGateway,
							fmt.Sprintf("%s: backend response not chained to sent UPP: previous signature does not match signature of request UPP\n"+
								" backend response was: (%d) %s", name, respCode, hex.EncodeToString(respBody)),
						)
						continue // todo persist or discard signature?
					}
					log.Debugf("%s: backend response chain verified", name)
				}

				// get request ID from backend response payload
				requestID, err = uuid.FromBytes(respUPP.GetPayload()[:16])
				if err != nil {
					log.Warnf("%s: unable to get request ID from backend response payload: %v\n backend response payload was: %q",
						name, err, respUPP.GetPayload())
				}
			}

			// check if request was successful
			if httpFailed(respCode) {
				log.Errorf("%s: request to UBIRCH Authentication Service (%s) failed: (%d) %q", name, conf.Niomon, respCode, respBody)

				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to load last signature for UUID %s: %v", name, err)
				}
			} else {
				if !isRespDecodable || !isRespChainedUPP {
					msg.Response <- HTTPErrorResponse(
						http.StatusBadGateway,
						fmt.Sprintf("backend responded with success status code but response is not verifiable\n"+
							" backend response was: (%d) %s", respCode, hex.EncodeToString(respBody)),
					)
					continue // todo persist or discard signature?
				}

				log.Debugf("%s: UPP successfully sent to %s", name, conf.Niomon)

				// save last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
				if err != nil {
					msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
					return fmt.Errorf("unable to persist last signature for UUID %s: %v", name, err)
				}
			}

			if requestID != uuid.Nil {
				log.Infof("%s: request ID: %s", name, requestID)
			}

			response, err := json.Marshal(map[string][]byte{
				"hash":      msg.Hash[:],
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
			msg.Response <- HTTPResponse{Code: respCode, Headers: respHeaders, Content: response}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}
