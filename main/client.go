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
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

// KeyRegistration is a certificate for a public key registered with the
// key-service.
type KeyRegistration struct {
	Algorithm      string `json:"algorithm"`
	Created        string `json:"created"`
	HwDeviceId     string `json:"hwDeviceId"`
	PubKey         string `json:"pubKey"`
	PubKeyId       string `json:"pubKeyId"`
	ValidNotAfter  string `json:"validNotAfter"`
	ValidNotBefore string `json:"validNotBefore"`
}

// SignedKeyRegistration is a signed certificate registered with the
// key-service.
type SignedKeyRegistration struct {
	PubKeyInfo KeyRegistration `json:"pubKeyInfo"`
	Signature  string          `json:"signature"`
}

// [WIP] this is a legacy method that will be replaced by CSR handling.
//
// This function will get the public key from the card and create a json registration package
// to be sent to the ubirch key service. The json structure is signed and sent to ubirch.
func getSignedCertificate(p *ExtendedProtocol, name string, uid uuid.UUID) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	cert, found := p.Certificates[uid]
	if !found { // there is no certificate stored yet
		// get the key
		pubKey, err := p.GetPublicKey(name)
		if err != nil {
			return nil, err
		}

		// decode the key
		block, _ := pem.Decode(pubKey)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the public key")
		}

		// extract X and Y from the key
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		pubKeyBytes := make([]byte, 0, 0)
		switch pub := pub.(type) {
		case *ecdsa.PublicKey:
			pubKeyBytes = append(pubKeyBytes, pub.X.Bytes()...)
			pubKeyBytes = append(pubKeyBytes, pub.Y.Bytes()...)
		default:
			return nil, errors.New("unknown type of public key")
		}
		pub64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

		// put it all together
		now := time.Now().UTC()
		keyRegistration := KeyRegistration{
			Algorithm:      "ecdsa-p256v1",
			Created:        now.Format(timeFormat),
			HwDeviceId:     uid.String(),
			PubKey:         pub64,
			PubKeyId:       pub64,
			ValidNotAfter:  now.Add(24 * 365 * time.Hour).Format(timeFormat),
			ValidNotBefore: now.Format(timeFormat),
		}

		// create string representation and sign it
		jsonKeyReg, err := json.Marshal(keyRegistration)
		if err != nil {
			return nil, err
		}

		signature, err := p.Sign(name, jsonKeyReg, ubirch.Plain)
		if err != nil {
			return nil, err
		}

		// fill the certificate
		cert.PubKeyInfo = keyRegistration
		cert.Signature = base64.StdEncoding.EncodeToString(signature)
		p.Certificates[uid] = cert
	}

	return json.Marshal(cert)
}

// submit a upp to a backend service, such as the key-service or niomon.
// it returns the status code, the response headers, the response body and
// encountered errors.
func post(upp []byte, url string, headers map[string]string) (int, map[string][]string, []byte, error) {
	// force HTTP/1.1 as HTTP/2 will break the headers on the server
	client := &http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(upp))
	if err != nil {
		log.Printf("can't make new post request: %v", err)
		return 0, nil, nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respContent, err := ioutil.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, respContent, err
}
