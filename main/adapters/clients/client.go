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
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	urlpkg "net/url"
)

type Client struct {
	AuthServiceURL     string
	VerifyServiceURL   string
	KeyServiceURL      string
	IdentityServiceURL string

	ServerTLSCertFingerprints map[string][32]byte
}

// RequestPublicKeys requests a devices public keys at the identity service
// returns a list of the retrieved public key certificates
func (c *Client) RequestPublicKeys(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error) {
	url := c.KeyServiceURL + "/current/hardwareId/" + id.String()

	resp, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key info: %v", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return []ubirch.SignedKeyRegistration{}, nil
	}

	if h.HttpFailed(resp.StatusCode) {
		return nil, fmt.Errorf("retrieving public key info from %s failed: (%d) %s", url, resp.StatusCode, string(resp.Content))
	}

	var keys []ubirch.SignedKeyRegistration
	err = json.Unmarshal(resp.Content, &keys)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key registration info: %v", err)
	}

	return keys, nil
}

// IsKeyRegistered sends a request to the identity service to determine
// if a specified public key is registered for the specified UUID
func (c *Client) IsKeyRegistered(id uuid.UUID, pubKey []byte) (bool, error) {
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

func (c *Client) SubmitKeyRegistration(uid uuid.UUID, cert []byte, auth string) error {
	log.Debugf("%s: registering public key at key service", uid)

	keyRegHeader := ubirchHeader(uid, auth)
	keyRegHeader["content-type"] = "application/json"

	resp, err := c.Post(c.KeyServiceURL, cert, &keyRegHeader)
	if err != nil {
		return fmt.Errorf("error sending key registration: %v", err)
	}
	if h.HttpFailed(resp.StatusCode) {
		return fmt.Errorf("key registration failed: (%d) %q", resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: key registration successful: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

// SubmitCSR submits a X.509 Certificate Signing Request for the public key to the identity service
func (c *Client) SubmitCSR(uid uuid.UUID, csr []byte) error {
	log.Debugf("%s: submitting CSR to identity service", uid)

	CSRHeader := map[string]string{"content-type": "application/octet-stream"}

	resp, err := c.Post(c.IdentityServiceURL, csr, &CSRHeader)
	if err != nil {
		return fmt.Errorf("error sending CSR: %v", err)
	}
	if h.HttpFailed(resp.StatusCode) {
		return fmt.Errorf("request to %s failed: (%d) %q", c.IdentityServiceURL, resp.StatusCode, resp.Content)
	}
	log.Debugf("%s: CSR submitted: (%d) %s", uid, resp.StatusCode, string(resp.Content))
	return nil
}

func (c *Client) Get(serviceURL string) (*h.HTTPResponse, error) {
	return c.makeRequest(http.MethodGet, serviceURL, nil, nil)
}

// Post submits a message to a backend service
// returns the response or encountered errors
func (c *Client) Post(serviceURL string, data []byte, header *map[string]string) (*h.HTTPResponse, error) {
	return c.makeRequest(http.MethodPost, serviceURL, data, header)
}

func (c *Client) makeRequest(method, serviceURL string, data []byte, header *map[string]string) (*h.HTTPResponse, error) {
	client, err := c.NewClientWithCertPinning(serviceURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, serviceURL, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to make new %s request: %v", method, err)
	}

	for k, v := range *header {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send %s request: %v", method, err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return &h.HTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Content:    respBodyBytes,
	}, nil
}

func (c *Client) SendToAuthService(uid uuid.UUID, auth string, upp []byte) (*h.HTTPResponse, error) {
	header := ubirchHeader(uid, auth)
	return c.Post(c.AuthServiceURL, upp, &header)
}

func ubirchHeader(uid uuid.UUID, auth string) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": uid.String(),
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(auth)),
	}
}

func (c *Client) NewClientWithCertPinning(url string) (*http.Client, error) {
	// get TLS certificate fingerprint for host
	u, err := urlpkg.Parse(url)
	if err != nil {
		return nil, err
	}
	tlsCertFingerprint, exists := c.ServerTLSCertFingerprints[u.Host]
	if !exists {
		return nil, fmt.Errorf("missing TLS certificate fingerprint for host %s", u.Host)
	}

	// set up TLS certificate verification
	client := &http.Client{Timeout: h.UpstreamRequestTimeout}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyConnection: NewConnectionVerifier(tlsCertFingerprint),
		},
	}
	return client, nil
}

// VerifyConnection is called after normal certificate verification and after VerifyPeerCertificate by
// either a TLS client or server. If it returns a non-nil error, the handshake is aborted and that error results.
//
// If normal verification fails then the handshake will abort before considering this callback. This callback will run
// for all connections regardless of InsecureSkipVerify or ClientAuth settings.
type VerifyConnection func(connectionState tls.ConnectionState) error

func NewConnectionVerifier(fingerprint [32]byte) VerifyConnection {
	return func(connectionState tls.ConnectionState) error {
		// PeerCertificates are the parsed certificates sent by the peer, in the order in which they were sent.
		// The first element is the leaf certificate that the connection is verified against.

		x509cert, err := x509.ParseCertificate(connectionState.PeerCertificates[0].Raw)
		if err != nil {
			return fmt.Errorf("parsing server x.509 certificate failed: %v", err)
		}

		serverCertFingerprint := sha256.Sum256(x509cert.RawSubjectPublicKeyInfo)

		if !bytes.Equal(serverCertFingerprint[:], fingerprint[:]) {
			return fmt.Errorf("pinned server TLS certificate mismatch")
		}

		return nil
	}
}
