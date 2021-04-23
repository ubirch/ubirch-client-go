package keystr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/youmark/pkcs8"
)

// EncryptedKeystore is the reference implementation for a simple keystr.
// The secret has to be 16 Bytes long
type EncryptedKeystore struct {
	Secret []byte
}

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) *EncryptedKeystore {
	if len(secret) != 32 {
		return nil
	}
	return &EncryptedKeystore{
		Secret:   secret,
	}
}

func (enc *EncryptedKeystore) Encryt(key []byte) ([]byte, error) {
	return pkcs8.ConvertPrivateKeyToPKCS8(key, enc.Secret)
}

func (enc *EncryptedKeystore) Decrypt(encryptedPrivateKey []byte) ([]byte, error) {
	keyECDSA, err := pkcs8.ParsePKCS8PrivateKeyECDSA(encryptedPrivateKey, enc.Secret)
	if err != nil {
		return nil, err
	}
	return encodePrivateKey(keyECDSA)
}

// encodePrivateKey encodes the Private Key as x509 and returns the encoded PEM // todo make these functions from ubirch.crypto public
func encodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

// encodePublicKey encodes the Public Key as x509 and returns the encoded PEM
func encodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return pemEncoded, nil
}