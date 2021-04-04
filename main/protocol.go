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
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"os"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	ctxManager         ContextManager
	contextFile_Legacy string
}

type ContextManager interface {
	LoadKeys(dest interface{}) error
	PersistKeys(source interface{}) error
	LoadSignatures(dest interface{}) error
	PersistSignatures(source interface{}) error
	Close() error
}

// Init sets keys in crypto context and updates keystore in persistent storage
func NewExtendedProtocol(secret []byte, cm ContextManager) (*ExtendedProtocol, error) {
	p := &ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(secret),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.ctxManager = cm

	err := p.portLegacyProtocolCtxFile()
	if err != nil {
		return nil, err
	}

	err = p.LoadKeys()
	if err != nil {
		return nil, err
	}

	err = p.LoadSignatures()
	if err != nil {
		return nil, err
	}

	if len(p.Signatures) != 0 {
		log.Printf("loaded existing protocol context: %d signatures", len(p.Signatures))
	}

	return p, nil
}

func (p *ExtendedProtocol) Deinit() error {
	return p.ctxManager.Close()
}

func (p *ExtendedProtocol) LoadKeys() error {
	return p.ctxManager.LoadKeys(&p.Crypto)
}

func (p *ExtendedProtocol) PersistKeys() error {
	return p.ctxManager.PersistKeys(&p.Crypto)
}

func (p *ExtendedProtocol) LoadSignatures() error {
	return p.ctxManager.LoadSignatures(&p.Signatures)
}

func (p *ExtendedProtocol) PersistSignatures() error {
	return p.ctxManager.PersistSignatures(&p.Signatures)
}

func (p *ExtendedProtocol) portLegacyProtocolCtxFile() error {
	if p.contextFile_Legacy == "" {
		return nil
	}
	if _, err := os.Stat(p.contextFile_Legacy); os.IsNotExist(err) { // if file does not exist, return right away
		return nil
	}

	// read legacy protocol context from persistent storage
	err := loadFile(p.contextFile_Legacy, p)
	if err != nil {
		return fmt.Errorf("unable to load protocol context: %v", err)
	}

	// persist loaded keys to new key storage
	err = p.PersistKeys()
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	// persist loaded signatures to new signature storage
	err = p.PersistSignatures()
	if err != nil {
		return fmt.Errorf("unable to persist signatures: %v", err)
	}

	// delete legacy protocol ctx file + bckup
	err = os.Remove(p.contextFile_Legacy)
	if err != nil {
		return fmt.Errorf("unable to delete legacy protocol context file: %v", err)
	}
	err = os.Remove(p.contextFile_Legacy + ".bck")
	if err != nil {
		log.Errorf("unable to delete legacy protocol context backup file: %v", err)
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
