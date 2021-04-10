package main

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

var (
	uid    = uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	key, _ = base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	payload = []byte("payload bytes")
)

func TestCoseSign(t *testing.T) {
	cryptoCtx := setupCrypto(t)

	coseSigner := NewCoseSigner(cryptoCtx)

	sigStruct := &Sig_structure{
		Context:         COSE_Sign1_Context,
		ProtectedHeader: ProtectedHeaderAlgES256,
		External:        []byte{}, // empty
		Payload:         payload,
	}

	toBeSigned, err := coseSigner.Marshal(sigStruct)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(toBeSigned)

	coseBytes, err := coseSigner.getSignedCOSE(uid, digest)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE: %x", coseBytes)
}

func setupCrypto(t *testing.T) ubirch.Crypto {
	cryptoCtx := &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore([]byte("1234567890123456")),
		Names:    map[string]uuid.UUID{},
	}

	err := cryptoCtx.SetKey(uid.String(), uid, key)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, _ := cryptoCtx.GetPublicKey(uid.String())
	t.Logf("public key: %x", pubKey)

	return cryptoCtx
}