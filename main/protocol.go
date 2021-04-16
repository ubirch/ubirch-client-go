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
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const contextFileName_Legacy = "protocol.json" // TODO: DEPRECATED

type ExtendedProtocol struct {
	ubirch.Protocol
	ContextManager
	Signatures map[uuid.UUID][]byte // this is here only for the purpose of backwards compatibility TODO: DEPRECATED
}

type ContextManager interface {
	LoadKeys(dest interface{}) error
	PersistKeys(source interface{}) error
	LoadSignature(uid uuid.UUID) ([]byte, error)
	PersistSignature(uid uuid.UUID, signature []byte) error
	LoadAuthToken(uid uuid.UUID) (string, error)
	PersistAuthToken(uid uuid.UUID, authToken string) error
	Close() error
}

func NewExtendedProtocol(cryptoCtx ubirch.Crypto, ctxManager ContextManager, configDir string) (*ExtendedProtocol, error) {
	p := &ExtendedProtocol{
		Protocol: ubirch.Protocol{
			Crypto: cryptoCtx,
		},
		ContextManager: ctxManager,
		Signatures:     map[uuid.UUID][]byte{},
	}

	err := p.portLegacyProtocolCtxFile(configDir)
	if err != nil {
		return nil, err
	}

	err = p.LoadKeys()
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *ExtendedProtocol) LoadKeys() error {
	return p.ContextManager.LoadKeys(&p.Crypto)
}

func (p *ExtendedProtocol) PersistKeys() error {
	return p.ContextManager.PersistKeys(&p.Crypto)
}

func (p *ExtendedProtocol) LoadSignature(uid uuid.UUID) ([]byte, error) {
	signature, err := p.ContextManager.LoadSignature(uid)
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

func (p *ExtendedProtocol) PersistSignature(uid uuid.UUID, signature []byte) error {
	err := p.checkSignatureLen(signature)
	if err != nil {
		return err
	}

	return p.ContextManager.PersistSignature(uid, signature)
}

func (p *ExtendedProtocol) checkSignatureLen(signature []byte) error {
	if len(signature) != p.SignatureLength() {
		return fmt.Errorf("invalid signature length: expected %d, got %d", p.SignatureLength(), len(signature))
	}
	return nil
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATED
func (p *ExtendedProtocol) portLegacyProtocolCtxFile(configDir string) error {
	contextFile_Legacy := filepath.Join(configDir, contextFileName_Legacy)

	if _, err := os.Stat(contextFile_Legacy); os.IsNotExist(err) { // if file does not exist, return right away
		return nil
	}

	// read legacy protocol context from persistent storage
	err := loadFile(contextFile_Legacy, p)
	if err != nil {
		return fmt.Errorf("unable to load protocol context: %v", err)
	}

	// persist loaded keys to new key storage
	err = p.PersistKeys()
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	// persist loaded signatures to new signature storage
	err = p.persistSignatures()
	if err != nil {
		return fmt.Errorf("unable to persist signatures: %v", err)
	}

	// delete legacy protocol ctx file + bckup
	err = os.Remove(contextFile_Legacy)
	if err != nil {
		return fmt.Errorf("unable to delete legacy protocol context file: %v", err)
	}
	err = os.Remove(contextFile_Legacy + ".bck")
	if err != nil {
		log.Warnf("unable to delete legacy protocol context backup file: %v", err)
	}

	return nil
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATED
func (p *ExtendedProtocol) persistSignatures() error {
	for uid, signature := range p.Signatures {
		err := p.PersistSignature(uid, signature)
		if err != nil {
			return err
		}
	}
	return nil
}

// Value lets the struct implement the driver.Valuer interface. This method
// simply returns the JSON-encoded representation of the struct.
func (p *ExtendedProtocol) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan lets the struct implement the sql.Scanner interface. This method
// simply decodes a JSON-encoded value into the struct fields.
func (p *ExtendedProtocol) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(b, p)
}
