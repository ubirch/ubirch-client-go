package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestCoseSign(t *testing.T) {
	key := "YUm0Xy475i7gnGNSnNJUriHQm33Uf+b/XHqZwjFluwM="
	keyBytes, _ := base64.StdEncoding.DecodeString(key)

	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(keyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	signer, err := NewCoseSigner(privKey)
	if err != nil {
		t.Fatal(err)
	}

	data := "hGpTaWduYXR1cmUxQ6EBJkBOc2lnbmVkIG1lc3NhZ2U=" //  b'\x84jSignature1C\xa1\x01&@Nsigned message'
	dataBytes, _ := base64.StdEncoding.DecodeString(data)
	hash := sha256.Sum256(dataBytes)

	coseBytes, err := CoseSign(signer, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%q", coseBytes)
	t.Logf("%x", coseBytes)
}
