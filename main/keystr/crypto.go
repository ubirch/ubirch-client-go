package keystr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
)

// EncryptedKeystore is the reference implementation for a simple keystr.
// The secret has to be 16 Bytes long
type EncryptedKeystore struct {
	Secret []byte
}

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) (*EncryptedKeystore, error) {
	if len(secret) != 32 {
		return nil,  fmt.Errorf("secret length must be 32 bytes (is %d)", len(secret))
	}
	return &EncryptedKeystore{
		Secret:   secret,
	}, nil
}

func (enc *EncryptedKeystore) Encrypt(privateKeyPem []byte) ([]byte, error) {
	privateKey, err := decodePrivateKey(privateKeyPem)
	if err != nil {
		return nil, err
	}
	return pkcs8.ConvertPrivateKeyToPKCS8(privateKey, enc.Secret)
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

// decodePrivateKey decodes a Private Key from the x509 PEM format and returns the Private Key
func decodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}