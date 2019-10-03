package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

////noinspection GoUnusedExportedType
type CertificateInterface interface {
	getSignedCertificate(p *ubirch.Protocol, name string, uid uuid.UUID) ([]byte, error)
}

// [WIP] this is a legacy method that will be replaced by CSR handling.
//
// This function will get the public key from the card and create a json registration package
// to be sent to the ubirch key service. The json structure is signed and sent to ubirch.
func getSignedCertificate(p *ubirch.Protocol, name string, uid uuid.UUID) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"
	// load a valid certificate from file
	var cert SignedKeyRegistration
	err := loadKeyCertificate(&cert, uid)
	if err != nil { // there is no certificate stored yet
		// get the key
		pubKey, err := p.GetKey(name)
		if err != nil {
			panic("key not available: " + err.Error())
		}
		// decode the key
		block, _ := pem.Decode(pubKey)
		if block == nil {
			panic("failed to parse PEM block containing the public key")
		}
		// extract X and Y from the key
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic("failed to parse DER encoded public key: " + err.Error())
		}
		pubKeyBytes := make([]byte, 0, 0)
		switch pub := pub.(type) {
		case *ecdsa.PublicKey:
			fmt.Println("pub is of type ECDSA:", pub)
			pubKeyBytes = append(pubKeyBytes, pub.X.Bytes()...)
			pubKeyBytes = append(pubKeyBytes, pub.Y.Bytes()...)
		default:
			panic("unknown type of public key")
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
		jsonKeyReg, err := json.Marshal(keyRegistration)
		if err != nil {
			return nil, err
		}
		keyHash := hash(jsonKeyReg)
		signature, err := p.Sign(name, keyHash, ubirch.Plain)
		if err != nil {
			return nil, err
		}
		//verifySignature(p,keyHash,uid)

		// fill the certificate
		cert.PubKeyInfo = keyRegistration
		cert.Signature = base64.StdEncoding.EncodeToString(signature)
		err = saveKeyCertificate(&cert, uid)
		if err != nil {
			// todo: storing went wrong
		}
	}

	return json.Marshal(cert)
}

func saveKeyCertificate(cert *SignedKeyRegistration, uid uuid.UUID) error {
	certString, _ := json.MarshalIndent(cert, "", "  ")
	filename := fmt.Sprintf("../%s_certificate.json", uid.String())
	err := ioutil.WriteFile(filename, certString, 444)
	if err != nil {
		log.Printf("unable to store key certificate: %v", err)
		return err
	} else {
		log.Printf("saved key certificate")
		return nil
	}
}

func loadKeyCertificate(cert *SignedKeyRegistration, uid uuid.UUID) (err error) {
	filename := fmt.Sprintf("../%s_certificate.json", uid.String())
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contextBytes, cert)
	if err != nil {
		log.Fatalf("unable to deserialize certificate: %v", err)
	} else {
		log.Printf("loaded key certificate")
	}
	return err
}

// Helper function to compute the SHA256 hash of the given string of bytes.
func hash(b []byte) []byte {
	h := sha256.New()
	// hash the body bytes
	h.Write(b)
	// compute the SHA256 hash
	return h.Sum(nil)
}

// post A http request to the backend service and
func post(upp []byte, url string, auth string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(upp))
	if err != nil {
		log.Printf("can't make new post request: %v", err)
		return nil, err
	} else {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			log.Printf("post failed; %v", err)
		}
		//noinspection GoUnhandledErrorResult
		defer resp.Body.Close()
		return ioutil.ReadAll(resp.Body)
	}
}

// verify the signature, CURRENTLY NOT USED
// the signature has to be hashed
func verifySignature(p *ubirch.Protocol, hashedSignature []byte, uid uuid.UUID) (err error) {
	var data = make([]byte, 0, 0)
	data = append(data, hashedSignature...)
	data = append(data, []byte{0xc4, 0x40}...)
	data = append(data, hashedSignature...)
	_, err = p.Crypto.Verify(uid, data)
	if err != nil {
		log.Println(err)
	}
	return err
}
