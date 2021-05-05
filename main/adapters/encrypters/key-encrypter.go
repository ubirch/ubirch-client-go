package encrypters

import (
	"fmt"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"github.com/youmark/pkcs8"
)

type KeyEncrypter struct {
	Secret []byte
	Crypto ubirch.Crypto
}

func NewKeyEncrypter(secret []byte, crypto ubirch.Crypto) (*KeyEncrypter, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("secret length for AES-256 encryption must be 32 bytes (is %d)", len(secret))
	}
	return &KeyEncrypter{
		Secret: secret,
		Crypto: crypto,
	}, nil
}

// Encrypt takes a PEM-encoded private key, AES256-encrypts it using a 32 byte secret
// and returns the encrypted DER-encoded PKCS#8 private key
func (enc *KeyEncrypter) Encrypt(privateKeyPem []byte) ([]byte, error) {
	privateKey, err := enc.Crypto.DecodePrivateKey(privateKeyPem)
	if err != nil {
		return nil, err
	}
	return pkcs8.ConvertPrivateKeyToPKCS8(privateKey, enc.Secret)
}

// Decrypt takes a AES256-encrypted DER-encoded PKCS#8 private key, decrypts it
// using a 32 byte secret and returns the decrypted PEM-encoded private key
func (enc *KeyEncrypter) Decrypt(encryptedPrivateKey []byte) (privateKeyPem []byte, err error) {
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(encryptedPrivateKey, enc.Secret)
	if err != nil {
		return nil, err
	}
	return enc.Crypto.EncodePrivateKey(privateKey)
}
