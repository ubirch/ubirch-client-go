package encrypters

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"testing"
)

func TestNewKeyEncrypter(t *testing.T) {
	testCases := []struct {
		name     string
		secret   []byte
		tcChecks func(t *testing.T, err error)
	}{
		{
			name:   "happy path",
			secret: []byte("c2VjcmV0ZWVldHR0dHR0dHR0dGVlCg=="),
			tcChecks: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:   "not 32 bytes",
			secret: []byte("c2VjcmV0ZWVldHR0dHR0dHR0dGVlCgddddd=="),
			tcChecks: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			crypto := &ubirch.ECDSACryptoContext{}
			_, err := NewKeyEncrypter(c.secret, crypto)
			c.tcChecks(t, err)
		})
	}
}

func TestDecryptedEncrypted(t *testing.T) {
	testCases := []struct {
		name     string
		tcChecks func(t *testing.T, err error)
	}{
		{
			name: "happy path",
			tcChecks: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			crypto := &ubirch.ECDSACryptoContext{}
			secret := []byte("c2VjcmV0ZWVldHR0dHR0dHR0dGVlCg==")

			keyEncrypter, err := NewKeyEncrypter(secret, crypto)
			require.NoError(t, err)

			key, err := keyEncrypter.Crypto.GenerateKey()
			require.NoError(t, err)
			fmt.Println(string(key))
			encryptPemVar, err := keyEncrypter.Encrypt(key)
			require.NoError(t, err)

			decryptPemVar, err := keyEncrypter.Decrypt(encryptPemVar)
			require.NoError(t, err)
			require.Equal(t, key, decryptPemVar)

		})
	}
}
