package main

import (
	"encoding/base64"
	"net/http"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"go.mozilla.org/cose"

	log "github.com/sirupsen/logrus"
)

type CoseSigner struct {
	cryptoCtx ubirch.Crypto
}

func (c *CoseSigner) Sign(msg HTTPRequest) HTTPResponse {
	log.Infof("%s: sign CBOR hash: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	coseBytes, err := c.getSignedCOSE(msg.ID, msg.Hash)
	if err != nil {
		log.Errorf("%s: could not create signed COSE: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}

	return HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Content:    coseBytes,
	}
}

func (c *CoseSigner) getSignedCOSE(id uuid.UUID, hash [32]byte) ([]byte, error) {
	// create ES256 signature
	signatureBytes, err := c.cryptoCtx.SignHash(id, hash[:])
	if err != nil {
		return nil, err
	}

	sig := cose.NewSignature()
	sig.Headers.Protected["alg"] = "ES256"
	sig.Headers.Unprotected["kid"] = id
	sig.SignatureBytes = signatureBytes

	// create COSE_Sign structure -> https://tools.ietf.org/html/rfc8152#section-4.1
	msg := cose.NewSignMessage()
	msg.Payload = hash[:]
	msg.AddSignature(sig)

	return msg.MarshalCBOR()
}
