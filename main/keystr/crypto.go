package keystr

import (
	"bytes"
	"crypto/aes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pkcs12"
)

// Base64Encoding to use when reading from or writing to
// a Keystore. Most clients will not need to change this.
var Base64Encoding = base64.StdEncoding

var (
	defaultIV   = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	alternateIV = []byte{0xA6, 0x59, 0x59, 0xA6}
)

// Keystore stores encrypted keys. The map is keyed by key name;
// value are encrypted, base64-encoded keys.
type Keystore struct {
	key string
}

// Get gets a key from the Keystore. kek is the key encrypting key.
func (ks Keystore) Encrypt(key string) ([]byte, error) {

	p12, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// head -c 32 /dev/urandom | base64

	blocks, err := pkcs12.ToPEM(p12) //TODO: , aes256)
	if err != nil {
		panic(err)
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	// then use PEM data for tls to construct tls certificate:
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		panic(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	config.Certificates[0].Certificate
}

// Set sets a key in the Keystore. kek is the key encrypting key.
func (ks Keystore) Set(keyname string, keyvalue []byte, kek []byte) error {
	switch {
	case len(keyname) == 0:
		return errors.New("empty keyname")
	case keyvalue == nil:
		return errors.New("nil keyvalue")
	case len(kek) != 16:
		return errors.New(fmt.Sprintf("invalid kek length (%d), must be 16", len(kek)))
	}

	klen := len(keyvalue)
	var keylen = klen
	if pad := klen % 8; pad != 0 {
		keylen = klen + 8 - pad
	}
	encryptedKey := make([]byte, keylen+8)
	ret := aesWrapKeyWithpad(kek, encryptedKey, keyvalue, uint(klen))

	if ret != keylen+8 {
		return errors.New("unable to wrap key")
	}
	encodedKey := Base64Encoding.EncodeToString(encryptedKey)
	ks[keyname] = encodedKey
	return nil
}

// RFC5649 implementation. Returns the len of encryptedKey, or -1 in case of failure.
func aesWrapKeyWithpad(key []byte, out []byte, in []byte, inlen uint) int {
	var ilen uint
	var ret int
	var input, iv []byte
	ret = -1

	if len(key) < 16 {
		return ret
	}
	cipher, err := aes.NewCipher(key)

	if inlen == 0 || err != nil || uint(len(in)) < inlen || uint(len(out)) < (inlen+8) {
		return ret
	}

	ilen = inlen
	if pad := inlen % 8; pad != 0 {
		ilen = ilen + 8 - pad
	}

	iv = make([]byte, 8)
	input = make([]byte, ilen+8)
	copy(iv, alternateIV[:4])
	binary.BigEndian.PutUint32(iv[4:], uint32(inlen))

	if ilen == 8 {
		copy(input, iv[:8])
		copy(input[8:], in[:inlen])
		cipher.Encrypt(out, input)
		ret = 8 + 8
	} else {
		copy(input, in[:inlen])
		ret = aesWrapKey(key, iv, out, input, ilen)
	}
	return ret
}

// RFC5649 implementation. Returns the length of the key, or -1 in case of failure.
func aesUnwrapKeyWithpad(key []byte, out []byte, in []byte, inlen uint) int {
	var padlen, ilen uint
	var ret = -1
	var aIV, zeroIV []byte

	if len(key) < 16 {
		return ret
	}
	cipher, err := aes.NewCipher(key)
	aIV = make([]byte, 8)
	zeroIV = make([]byte, 8)

	if (inlen&0x7) != 0 || inlen < 16 || err != nil || uint(len(in)) < inlen || uint(len(out)) < 16 {
		return ret
	}

	if inlen == 16 {
		cipher.Decrypt(out, in)
		copy(aIV, out[:8])
		copy(out, out[8:16])
	} else {
		if aesUnwrapKey(key, nil, out, in, inlen, aIV) <= 0 {
			return ret
		}
	}

	if !bytes.Equal(aIV[:4], alternateIV[:4]) {
		return ret
	}

	ilen = uint(binary.BigEndian.Uint32(aIV[4:8]))
	inlen -= 8

	if ilen > inlen || ilen <= (inlen-8) {
		return ret
	}

	padlen = inlen - ilen

	if padlen != 0 && !bytes.Equal(zeroIV[:padlen], out[ilen:ilen+padlen]) {
		return ret
	}

	return int(ilen)
}

// RFC3394 implementation. Returns the length of the encrypted key, or -1 in case of failure.
func aesWrapKey(key []byte, iv []byte, out []byte, in []byte, inlen uint) int {
	var A, B, R []byte
	var i, j, t uint
	var ret = -1
	B = make([]byte, 16)

	if len(key) < 16 {
		return ret
	}
	cipher, err := aes.NewCipher(key)

	if (inlen&0x7) != 0 || (inlen < 8) || err != nil || uint(len(out)) < 16 || uint(len(in)) < inlen {
		return ret
	}

	A = B
	t = 1

	copy(out[8:], in[:inlen])
	if iv == nil {
		iv = defaultIV
	}
	copy(A, iv[:8])

	for j = 0; j < 6; j++ {
		R = out[8:]
		for i = 0; i < inlen; i, t, R = i+8, t+1, R[8:] {
			copy(B[8:], R[:8])
			cipher.Encrypt(B, B)
			A[7] ^= uint8(t & 0xff)
			if t > 0xff {
				A[6] ^= uint8((t >> 8) & 0xff)
				A[5] ^= uint8((t >> 16) & 0xff)
				A[4] ^= uint8((t >> 24) & 0xff)
			}
			copy(R, B[8:16])
		}
	}
	copy(out, A[:8])
	return int(inlen + 8)
}

// RFC3394 implementation. Returns the length of the key, or -1 in case of failure.
func aesUnwrapKey(key []byte, iv []byte, out []byte, in []byte, inlen uint, aIV []byte) int {
	var A, B, R []byte
	var i, j, t uint
	var ret = -1
	B = make([]byte, 16)

	if len(key) < 16 {
		return ret
	}
	cipher, err := aes.NewCipher(key)

	inlen -= 8
	if (inlen&0x7) != 0 || (inlen < 8) || err != nil || uint(len(out)) < (inlen-8) || uint(len(in)) < inlen {
		return ret
	}

	A = B
	t = 6 * (inlen >> 3)

	copy(A, in[:8])
	copy(out, in[8:inlen+8])

	for j = 0; j < 6; j++ {
		for i = 0; i < inlen; i, t = i+8, t-1 {
			R = out[inlen-8-i:]
			A[7] ^= uint8(t & 0xff)
			if t > 0xff {
				A[6] ^= uint8((t >> 8) & 0xff)
				A[5] ^= uint8((t >> 16) & 0xff)
				A[4] ^= uint8((t >> 24) & 0xff)
			}
			copy(B[8:], R[:8])
			cipher.Decrypt(B, B)
			copy(R, B[8:16])
		}
	}

	if aIV != nil {
		copy(aIV, A[:8])
	} else {
		if iv == nil {
			iv = defaultIV
		}
		if !bytes.Equal(A[:8], iv[:8]) {
			return ret
		}
	}
	return int(inlen)
}
