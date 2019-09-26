/*
 * Copyright (c) 2019 ubirch GmbH.
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

package ubirch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"math/big"
)

// This crypto context contains the key store, a mapping for names -> UUIDs
// and the last generated signature per UUID.
type CryptoContext struct {
	Keystore *keystore.Keystore
	Names    map[string]uuid.UUID
}

func encodePriv(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

func encodePub(publicKey *ecdsa.PublicKey) ([]byte, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, nil
}

func decodePriv(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

func decodePub(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

func signatureToPoints(signature []byte) (r, s *big.Int, err error) {
	r, s = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	_, err = asn1.Unmarshal(signature, &data)
	if err != nil {
		return nil, nil, err
	}

	rLen := data.Bytes[1]
	r.SetBytes(data.Bytes[2 : rLen+2])
	s.SetBytes(data.Bytes[rLen+4:])

	return r, s, nil
}

func (c *CryptoContext) storePublicKey(name string, id uuid.UUID, k *ecdsa.PublicKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	pubKeyBytes, err := encodePub(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set("_"+id.String(), pubKeyBytes, pph)
}

func (c *CryptoContext) storePrivateKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	privKeyBytes, err := encodePriv(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set(id.String(), privKeyBytes, pph)
}

func (c *CryptoContext) storeKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	err := c.storePublicKey(name, id, &k.PublicKey)
	if err != nil {
		return err
	}
	return c.storePrivateKey(name, id, k)
}

// Get the uuid that is related the given name.
func (c *CryptoContext) GetUUID(name string) (uuid.UUID, error) {
	id, found := c.Names[name]
	if !found {
		return uuid.Nil, errors.New(fmt.Sprintf("no uuid/key entry for '%s'", name))
	}
	return id, nil
}

// Generate a new key pair and store it using the given name and associated UUID.
func (c *CryptoContext) GenerateKey(name string, id uuid.UUID) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	return c.storeKey(name, id, k)
}

// Get a certificate signing request.
func (c *CryptoContext) GetCSR(name string) ([]byte, error) { return nil, nil }

// Get the public key bytes for the given name.
func (c *CryptoContext) GetKey(name string) ([]byte, error) {
	id, err := c.GetUUID(name)
	if err != nil {
		return nil, err
	}

	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := c.Keystore.Get("_"+id.String(), pph)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}

// Sign a message using a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	pph, _ := id.MarshalBinary()
	privKeyBytes, err := c.Keystore.Get(id.String(), pph)
	priv, err := decodePriv(privKeyBytes)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, data)
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// Verify a message using a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Verify(id uuid.UUID, data []byte) ([]byte, error) {
	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := c.Keystore.Get("_"+id.String(), pph)
	if err != nil {
		return nil, err
	}

	pub, err := decodePub(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	r, s, err := signatureToPoints(data[len(data)-66:])
	if err != nil {
		return nil, err
	}

	value := data[0 : len(data)-64]
	if ecdsa.Verify(pub, value, r, s) {
		return value, nil
	}
	return nil, errors.New("signature verification failed")
}
