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
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
	"math/rand"
	"time"
)

type ProtocolType uint8

const (
	Plain   ProtocolType = 0x01
	Signed  ProtocolType = 0x22
	Chained ProtocolType = 0x23
)

type Crypto interface {
	GetUUID(name string) (uuid.UUID, error)
	GenerateKey(name string, id uuid.UUID) error
	GetCSR(name string) ([]byte, error)
	GetKey(name string) ([]byte, error)

	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, value []byte) ([]byte, error)
}

type Protocol struct {
	Crypto
	Signatures map[uuid.UUID][]byte
}

type signed struct {
	Version   ProtocolType
	Uuid      uuid.UUID
	Hint      uint8
	Payload   []byte
	Signature []byte
}

type chained struct {
	Version       ProtocolType
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          uint8
	Payload       []byte
	Signature     []byte
}

func encode(v interface{}) ([]byte, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	encoded := make([]byte, 128)
	encoder := codec.NewEncoderBytes(&encoded, &mh)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return encoded, nil
}

func appendSignature(encoded []byte, signature []byte) []byte {
	encoded = append(encoded[:len(encoded)-1], 0xC4, byte(len(signature)))
	encoded = append(encoded, signature...)
	return encoded
}

func (upp signed) sign(p *Protocol) ([]byte, error) {
	encoded, err := encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	return appendSignature(encoded, signature), nil
}

func (upp chained) sign(p *Protocol) ([]byte, error) {
	encoded, err := encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	p.Signatures[upp.Uuid] = signature
	return appendSignature(encoded, signature), nil
}

func (p *Protocol) Init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func (p *Protocol) Random(len int) ([]byte, error) {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(rand.Intn(255))
	}
	return bytes, nil
}

// Create and sign a ubirch-protocol message using the given data and the protocol type.
// The method expects a hash as input data for the value.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *Protocol) Sign(name string, value []byte, protocol ProtocolType) ([]byte, error) {
	id, err := p.Crypto.GetUUID(name)
	if err != nil {
		return nil, err
	}

	switch protocol {
	case Plain:
		return p.Crypto.Sign(id, value)
	case Signed:
		return signed{protocol, id, 0x00, value, nil}.sign(p)
	case Chained:
		signature, found := p.Signatures[id]
		if !found {
			signature = make([]byte, 64)
		}
		return chained{protocol, id, signature, 0x00, value, nil}.sign(p)
	default:
		return nil, errors.New(fmt.Sprintf("unknown protocol type: 0x%02x", protocol))
	}
}

// Verify a ubirch-protocol message and return the payload.
func (p *Protocol) Verify(name string, value []byte, protocol int) (bool, error) {
	return true, nil
}
