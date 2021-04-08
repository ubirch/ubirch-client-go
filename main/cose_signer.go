package main

import (
	"crypto"
	"crypto/rand"
	"go.mozilla.org/cose"
)

func NewCoseSigner(privateKey crypto.PrivateKey) (signer *cose.Signer, err error) {
	//Algorithm{
	//	Name:               "ES256", // ECDSA w/ SHA-256 from [RFC8152]
	//	Value:              -7,
	//	HashFunc:           crypto.SHA256,
	//	privateKeyType:     KeyTypeECDSA,
	//	privateKeyECDSACurve:    elliptic.P256(),
	//}

	//type Signer struct {
	//	PrivateKey crypto.PrivateKey
	//	alg        *Algorithm
	//}

	// create a signer with a new private key
	return cose.NewSignerFromKey(cose.ES256, privateKey)
}

func CoseSign(signer *cose.Signer, cborSHA256 []byte) ([]byte, error) {
	//type Headers struct {
	//	Protected   map[interface{}]interface{}
	//	Unprotected map[interface{}]interface{}
	//}

	//type Signature struct {
	//	Headers        *Headers
	//	SignatureBytes []byte
	//}

	//type SignMessage struct {
	//	Headers    *Headers
	//	Payload    []byte
	//	Signatures []Signature
	//}

	// create a signature
	sig := cose.NewSignature()
	sig.Headers.Protected["alg"] = "ES256"
	sig.Headers.Unprotected["kid"] = 1

	msg := cose.NewSignMessage()
	msg.Payload = cborSHA256
	msg.AddSignature(sig)

	//err := msg.Sign(rand.Reader, nil, []cose.Signer{*signer})
	signatureBytes, err := signer.Sign(rand.Reader, cborSHA256)
	if err != nil {
		return nil, err
	}
	msg.Signatures[0].SignatureBytes = signatureBytes

	return msg.MarshalCBOR()
}
