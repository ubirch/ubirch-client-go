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
)

type KeyRegistration struct {
	Algorithm      string `json:"algorithm"`
	Created        string `json:"created"`
	HwDeviceId     string `json:"hwDeviceId"`
	PubKey         string `json:"pubKey"`
	PubKeyId       string `json:"pubKeyId"`
	ValidNotAfter  string `json:"validNotAfter"`
	ValidNotBefore string `json:"validNotBefore"`
}

type SignedKeyRegistration struct {
	PubKeyInfo KeyRegistration `json:"pubKeyInfo"`
	Signature  string          `json:"signature"`
}

// [WIP] this is a legacy method that will be replaced by CSR handling.
//
// This function will get the public key from the card and create a json registration package
// to be sent to the ubirch key service. The json structure is signed and sent to ubirch.
func getSignedCertificate(p *ExtendedProtocol, name string) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	// get the UUID
	uid, err := p.Crypto.GetUUID(name)
	if err != nil {
		return nil, err
	}

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
		paddedX := make([]byte, 32)
		paddedY := make([]byte, 32)
		copy(paddedX[32-len(pub.X.Bytes()):], pub.X.Bytes())
		copy(paddedY[32-len(pub.Y.Bytes()):], pub.Y.Bytes())
		pubKeyBytes = append(pubKeyBytes, paddedX...)
		pubKeyBytes = append(pubKeyBytes, paddedY...)
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
		ValidNotAfter:  now.Add(10 * 365 * 24 * time.Hour).Format(timeFormat), // valid for 10 years
		ValidNotBefore: now.Format(timeFormat),
	}

	// create string representation and sign it
	jsonKeyReg, err := json.Marshal(keyRegistration)
	if err != nil {
		return nil, err
	}

	signature, err := p.Crypto.Sign(uid, jsonKeyReg)
	if err != nil {
		return nil, err
	}

	// fill the certificate
	cert := SignedKeyRegistration{
		PubKeyInfo: keyRegistration,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	return json.Marshal(cert)
}

// submit a UPP to a backend service, such as the key-service or niomon.
// returns the response status code, the response headers, the response body and encountered errors.
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
