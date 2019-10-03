package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/thinkberg/ubirch-protocol-go/ubirch"
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
func getSignedCertificate(p *ExtendedProtocol, name string, uid uuid.UUID) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	cert, found := p.Certificates[uid]
	if !found { // there is no certificate stored yet
		// get the key
		pubKey, err := p.GetKey(name)
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
		now := time.Now()
		keyRegistration := KeyRegistration{
			"ecdsa-p256v1",
			now.Format(timeFormat),
			uid.String(),
			string(pub64),
			string(pub64),
			now.Add(time.Duration(24 * 365 * time.Hour)).Format(timeFormat),
			now.Format(timeFormat),
		}

		// create string representation and sign it
		jsonKeyReg, err := json.Marshal(keyRegistration)
		if err != nil {
			return nil, err
		}

		keyHash := sha256.Sum256(jsonKeyReg)
		signature, err := p.Sign(name, keyHash[:], ubirch.Plain)
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

// post A http request to the backend service and
func post(upp []byte, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(upp))
	if err != nil {
		log.Printf("can't make new post request: %v", err)
		return nil, err
	} else {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		//req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			log.Printf("post failed; %v", err)
		}
		//noinspection GoUnhandledErrorResult
		defer resp.Body.Close()
		return ioutil.ReadAll(resp.Body)
	}
}
