package main

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

func TestCoseSign(t *testing.T) {
	uid := uuid.MustParse("d1b7eb09-d1d8-4c63-b6a5-1c861a6477fa")
	key, _ := base64.StdEncoding.DecodeString("YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM=")

	cryptoCtx := &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore([]byte("1234567890123456")),
		Names:    map[string]uuid.UUID{},
	}

	err := cryptoCtx.SetKey(uid.String(), uid, key)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, _ := cryptoCtx.GetPublicKey(uid.String())
	t.Logf("%s: public key: %x", uid, pubKey)

	coseSigner := NewCoseSigner(cryptoCtx)

	cborBytes := []byte("\\x84jSignature1C\\xa1\\x01&@Nsigned message")
	cborHash := sha256.Sum256(cborBytes)

	coseBytes, err := coseSigner.getSignedCOSE(uid, cborHash)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("signed COSE: %x", coseBytes)
}
