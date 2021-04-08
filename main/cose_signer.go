package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"go.mozilla.org/cose"
)

type CoseSigner struct {
	ubirch.Crypto
}

func (c *CoseSigner) Sign(id uuid.UUID, cborSHA256 []byte) ([]byte, error) {
	if len(cborSHA256) != c.HashLength() {
		return nil, fmt.Errorf("invalid hash size: expected %d, got %d bytes", c.HashLength(), len(cborSHA256))
	}

	// create ES256 signature
	signatureBytes, err := c.Crypto.Sign(id, cborSHA256)
	if err != nil {
		return nil, err
	}

	sig := cose.NewSignature()
	sig.Headers.Protected["alg"] = "ES256"
	sig.Headers.Unprotected["kid"] = id
	sig.SignatureBytes = signatureBytes

	// create COSE_Sign structure -> https://tools.ietf.org/html/rfc8152#section-4.1
	msg := cose.NewSignMessage()
	msg.Payload = cborSHA256
	msg.AddSignature(sig)

	return msg.MarshalCBOR()
}
