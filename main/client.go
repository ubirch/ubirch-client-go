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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
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

type Client struct {
	authServiceURL      string
	verifyServiceURL    string
	keyServiceURL       string
	identityServiceURL  string
	subjectCountry      string
	subjectOrganization string
}

// requestPublicKeys requests a devices public keys at the identity service
// returns a list of the retrieved public key certificates
func (c *Client) requestPublicKeys(id uuid.UUID) ([]SignedKeyRegistration, error) {
	url := c.keyServiceURL + "/current/hardwareId/" + id.String()
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key info: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []SignedKeyRegistration{}, nil
	}

	if httpFailed(resp.StatusCode) {
		respContent, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key info from %s failed: (%s) %s", url, resp.Status, string(respContent))
	}

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	var keys []SignedKeyRegistration
	err = json.Unmarshal(respBodyBytes, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key registration info: %v", err)
	}

	return keys, nil
}

// isKeyRegistered sends a request to the identity service to determine
// if a specified public key is registered for the specified UUID
func (c *Client) isKeyRegistered(id uuid.UUID, pubKey []byte) (bool, error) {
	certs, err := c.requestPublicKeys(id)
	if err != nil {
		return false, err
	}

	for _, cert := range certs {
		if cert.PubKeyInfo.PubKey == base64.StdEncoding.EncodeToString(pubKey) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) registerPublicKey(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte, auth string) error {
	log.Infof("%s: registering public key at key service", uid)

	cert, err := getSignedCertificate(p, uid, pubKey)
	if err != nil {
		return fmt.Errorf("error creating public key certificate: %v", err)
	}
	log.Debugf("%s: certificate: %s", uid, cert)

	keyRegHeader := ubirchHeader(uid, auth)
	keyRegHeader["content-type"] = "application/json"

	resp, err := post(c.keyServiceURL, cert, keyRegHeader)
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if httpFailed(resp.StatusCode) {
		return fmt.Errorf("key registration failed: (%d) %q", resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: key registration successful: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

// submitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func (c *Client) submitCSR(p *ExtendedProtocol, uid uuid.UUID) error {
	log.Debugf("%s: submitting CSR to identity service", uid)

	csr, err := p.GetCSR(uid, c.subjectCountry, c.subjectOrganization)
	if err != nil {
		return fmt.Errorf("error creating CSR: %v", err)
	}
	log.Debugf("%s: CSR [der]: %x", uid, csr)

	CSRHeader := map[string]string{"content-type": "application/octet-stream"}

	resp, err := post(c.identityServiceURL, csr, CSRHeader)
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if httpFailed(resp.StatusCode) {
		return fmt.Errorf("request to %s failed: (%d) %q", c.identityServiceURL, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: CSR submitted: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

func (c *Client) sendToAuthService(uid uuid.UUID, auth string, upp []byte) (HTTPResponse, error) {
	return post(c.authServiceURL, upp, ubirchHeader(uid, auth))
}

// getSignedCertificate creates a self-signed JSON key certificate
// to be sent to the identity service for public key registration
func getSignedCertificate(p *ExtendedProtocol, uid uuid.UUID, pubKey []byte) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	// put it all together
	now := time.Now().UTC()
	keyRegistration := KeyRegistration{
		Algorithm:      "ecdsa-p256v1",
		Created:        now.Format(timeFormat),
		HwDeviceId:     uid.String(),
		PubKey:         base64.StdEncoding.EncodeToString(pubKey),
		PubKeyId:       base64.StdEncoding.EncodeToString(pubKey),
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

// post submits a message to a backend service
// returns the response or encountered errors
func post(serviceURL string, data []byte, header map[string]string) (HTTPResponse, error) {
	client := &http.Client{Timeout: BackendRequestTimeout}

	req, err := http.NewRequest(http.MethodPost, serviceURL, bytes.NewBuffer(data))
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("can't make new post request: %v", err)
	}

	for k, v := range header {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return HTTPResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return HTTPResponse{}, err
	}

	return HTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Content:    respBodyBytes,
	}, nil
}

func ubirchHeader(uid uuid.UUID, auth string) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": uid.String(),
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(auth)),
	}
}

func httpFailed(StatusCode int) bool {
	return !httpSuccess(StatusCode)
}

func httpSuccess(StatusCode int) bool {
	return StatusCode >= 200 && StatusCode < 300
}
