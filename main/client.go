package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/thinkberg/ubirch-protocol-go/ubirch"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

////noinspection GoUnusedExportedType
type CertificateInterface interface {
	getSignedCertificate(p *ubirch.Protocol, name string, uid uuid.UUID) ([]byte, error)
}

// [WIP] this is a legacy method that will be replaced by CSR handling.
//
// This function will get the public key from the card and create a json registration package
// to be sent to the ubirch key service. The json structure is signed and sent to ubirch.
func getSignedCertificate(p *ubirch.Protocol, name string, uid uuid.UUID) ([]byte, error) {
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
	const timeFormat = "2006-01-02T15:04:05.000Z"

	pubKey, err := p.GetKey(name)
	var pubKeyPure = make([]byte, 0, 0)
	if err != nil {
		return nil, err
	} else {
		n1 := strings.Index(string(pubKey), "\n") + 1
		n2 := strings.Index(string(pubKey[n1:]), "\n") + n1 + 1
		n3 := strings.Index(string(pubKey[n2:]), "\n") + n2 + 1
		pubKeyPure = append(pubKeyPure, pubKey[n1:n2-1]...)
		pubKeyPure = append(pubKeyPure, pubKey[n2:n3-1]...)
	}
	fmt.Println("PUREKEY:", string(pubKey))

	block, _ := pem.Decode(pubKey)
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	// this is just to prove that the key is in the right format
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	default:
		panic("unknown type of public key")
	}

	type publicKeyInfo struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	bitString := publicKeyInfo{}
	_, err = asn1.Unmarshal(block.Bytes, &bitString)
	if err != nil {
		log.Fatal(err)
	}
	pubKeyBytes := bitString.PublicKey.Bytes[1:]
	fmt.Printf("hexkey (%d) %x\n", len(pubKeyBytes), pubKeyBytes)
	// ich brauch bitString.PublicKey.Bytes
	pub64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
	fmt.Println("BLOCK", pub64)

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
	log.Print("jsonKeyReg:", string(jsonKeyReg))

	signatureTestString := "Ubirch TestString"

	signature, err := p.Sign(name, []byte(signatureTestString), ubirch.Plain)
	if err != nil {
		return nil, err
	}
	fmt.Println("cap:", cap(signature), "len:", len(signature), "var:", hex.EncodeToString(signature))
	var data = make([]byte, 0, 0)
	data = append(data, []byte(signatureTestString)...)
	data = append(data, []byte{0xc4, 0x40}...)
	data = append(data, signature...)
	fmt.Println(len(data))
	_, err = p.Crypto.Verify(uid, data)
	log.Println(err)

	return json.Marshal(SignedKeyRegistration{
		keyRegistration,
		base64.StdEncoding.EncodeToString(signature),
	})
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
