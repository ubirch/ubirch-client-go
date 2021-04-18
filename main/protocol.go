// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
}

type ContextManager interface {
	StartTransaction(uid uuid.UUID) error
	EndTransaction(uid uuid.UUID) error

	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	SetPrivateKey(uid uuid.UUID, key []byte) error

	GetPublicKey(uid uuid.UUID) ([]byte, error)
	SetPublicKey(uid uuid.UUID, key []byte) error

	GetSignature(uid uuid.UUID) ([]byte, error)
	SetSignature(uid uuid.UUID, signature []byte) error

	GetAuthToken(uid uuid.UUID) (string, error)
	SetAuthToken(uid uuid.UUID, authToken string) error

	DeleteIdentity(uid uuid.UUID) error
	Close() error
}

func NewExtendedProtocol(cryptoCtx ubirch.Crypto, ctxManager ContextManager) (*ExtendedProtocol, error) {
	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: cryptoCtx,
		},
		ContextManager: ctxManager,
	}

	return p, nil
}

func (p *ExtendedProtocol) GetSignature(uid uuid.UUID) ([]byte, error) {
	signature, err := p.ContextManager.GetSignature(uid)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]byte, p.SignatureLength()), nil
		} else {
			return nil, err
		}
	}

	err = p.checkSignatureLen(signature)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (p *ExtendedProtocol) SetSignature(uid uuid.UUID, signature []byte) error {
	err := p.checkSignatureLen(signature)
	if err != nil {
		return err
	}

	return p.ContextManager.SetSignature(uid, signature)
}

func (p *ExtendedProtocol) checkSignatureLen(signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}
	return nil
}
