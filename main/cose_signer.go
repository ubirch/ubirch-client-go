package main

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"go.mozilla.org/cose"
)

type CoseSigner struct {
	ubirch.Crypto
}

func (c *CoseSigner) Sign(id uuid.UUID, cborSHA256 [32]byte) ([]byte, error) {
	// create ES256 signature
	signatureBytes, err := c.Crypto.SignHash(id, cborSHA256[:])
	if err != nil {
		return nil, err
	}

	sig := cose.NewSignature()
	sig.Headers.Protected["alg"] = "ES256"
	sig.Headers.Unprotected["kid"] = id
	sig.SignatureBytes = signatureBytes

	// create COSE_Sign structure -> https://tools.ietf.org/html/rfc8152#section-4.1
	msg := cose.NewSignMessage()
	msg.Payload = cborSHA256[:]
	msg.AddSignature(sig)

	return msg.MarshalCBOR()
}
