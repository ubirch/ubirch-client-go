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

package clients

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	urlpkg "net/url"
)

type IdentityServiceClient struct {
	KeyServiceURL          string
	IdentityServiceURL     string
	IdentityServiceTimeout time.Duration
}

// RequestPublicKeys requests a devices public keys at the identity service
// returns a list of the retrieved public key certificates
func (c *IdentityServiceClient) RequestPublicKeys(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error) {
	url, err := urlpkg.Parse(c.KeyServiceURL)
	if err != nil {
		return nil, fmt.Errorf("key service URL could not be parsed: %v", err)
	}
	url.Path = path.Join(url.Path, "current/hardwareId", id.String())
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key info: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []ubirch.SignedKeyRegistration{}, nil
	}

	if h.HttpFailed(resp.StatusCode) {
		respContent, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrieving public key info from %s failed: (%s) %s", url, resp.Status, string(respContent))
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	var keys []ubirch.SignedKeyRegistration
	err = json.Unmarshal(respBodyBytes, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key registration info: %v", err)
	}

	return keys, nil
}

// IsKeyRegistered sends a request to the identity service to determine
// if a specified public key is registered for the specified UUID
func (c *IdentityServiceClient) IsKeyRegistered(id uuid.UUID, pubKey []byte) (bool, error) {
	certs, err := c.RequestPublicKeys(id)
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

func (c *IdentityServiceClient) SubmitKeyRegistration(uid uuid.UUID, cert []byte) error {
	log.Debugf("%s: registering public key at key service: %s, cert: %s", uid, c.KeyServiceURL, cert)

	keyRegHeader := map[string]string{"content-type": "application/json"}

	resp, err := sendRequest(http.MethodPost, c.KeyServiceURL, cert, keyRegHeader, c.IdentityServiceTimeout)
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if h.HttpFailed(resp.StatusCode) {
		return fmt.Errorf("key registration unsuccessful: request to %s failed: (%d) %q", c.KeyServiceURL, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: key registration successful: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

func (c *IdentityServiceClient) RequestKeyDeletion(uid uuid.UUID, cert []byte) error {
	log.Debugf("%s: deleting public key at key service", uid)

	keyDelHeader := map[string]string{"content-type": "application/json"}

	resp, err := sendRequest(http.MethodDelete, c.KeyServiceURL, cert, keyDelHeader, c.IdentityServiceTimeout)
	if err != nil {
		return fmt.Errorf("error sending key deletion request: %v", err)
	}
	if h.HttpFailed(resp.StatusCode) {
		return fmt.Errorf("key deletion unsuccessful: request to %s failed: (%d) %q", c.KeyServiceURL, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: key deletion successful: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

// SubmitCSR submits an X.509 Certificate Signing Request for the public key to the identity service
func (c *IdentityServiceClient) SubmitCSR(uid uuid.UUID, csr []byte) error {
	log.Debugf("%s: submitting CSR to identity service", uid)

	CSRHeader := map[string]string{"content-type": "application/octet-stream"}

	resp, err := sendRequest(http.MethodPost, c.IdentityServiceURL, csr, CSRHeader, c.IdentityServiceTimeout)
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if h.HttpFailed(resp.StatusCode) {
		return fmt.Errorf("CSR submission unsuccessful: request to %s failed: (%d) %q", c.IdentityServiceURL, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: CSR submitted: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}
