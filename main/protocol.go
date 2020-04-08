/*
 * Copyright (c) 2019 ubirch GmbH
 *
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
 */

package main

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[string]SignedKeyRegistration
	DB           Database
	Path         string
}

// INIT sets keys in crypto context and automatically updates keystore in persistent storage
func (p *ExtendedProtocol) Init(dsn string, keys map[string]string) error {
	// check if we want to use a database as persistent storage
	if dsn != "" {
		// use the database
		db, err := NewPostgres(dsn)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		p.DB = db
	}

	// try to read an existing protocol context from persistent storage (keystore, last signatures, key certificates)
	err := p.LoadContext()
	if err != nil {
		log.Printf("unable to load protocol context: %v", err)
	} else {
		log.Printf("loaded protocol context")
		log.Printf("%d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))
	}

	// set whitelist keys in crypto context
	for name, key := range keys {
		uid, err := uuid.Parse(name)
		if err != nil {
			return fmt.Errorf("unable to parse key name %s from key map to UUID: %v", name, err)
		}
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("unable to decode private key string for %s: %v, string was: %s", name, err, key)
		}
		err = p.Crypto.SetKey(name, uid, keyBytes)
		if err != nil {
			return fmt.Errorf("unable to insert private key to protocol context: %v", err)
		}
	}

	// update keystore in persistent storage // todo is this even necessary?
	err = p.PersistKeystore()
	if err != nil {
		log.Printf("unable to store key pairs: %v\n", err)
	}

	return nil
}

// LoadContext loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) LoadContext() error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.Path + ContextFile)
	}
}

func (p *ExtendedProtocol) LoadKeystore() error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.Path+ContextKeystoreFile, p.Crypto.Keystore) // fixme this is why we currently can not load keys from persistent memory into protocol instance
	}
}

func (p *ExtendedProtocol) LoadCertificates(id uuid.UUID) error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.Path+ContextCertificatesFile, p.Certificates)
	}
}

func (p *ExtendedProtocol) LoadLastSignature(id uuid.UUID) error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.Path+ContextSignaturesFile, p.Signatures)
	}
}

// PersistContext saves current ubirch-protocol context, storing keystore, key certificates and signatures
func (p *ExtendedProtocol) PersistContext() error {
	if p.DB != nil {
		return p.DB.SetProtocolContext(p)
	} else {
		return p.saveFile(p.Path + ContextFile)
	}
}

// PersistKeystore stores keys persistently
func (p *ExtendedProtocol) PersistKeystore() error {
	if p.DB != nil {
		return p.DB.PersistKeystore(p.GetKeystorer())
	} else {
		return p.saveFile(p.GetKeystorer(), p.Path+ContextKeystoreFile)
	}
}

// PersistCertificates stores key certificates persistently
func (p *ExtendedProtocol) PersistCertificates(id uuid.UUID) error {
	if p.DB != nil {
		// todo
		return p.DB.SetProtocolContext(p)
	} else {
		return p.saveFile(p.Certificates, p.Path+ContextCertificatesFile)
	}
}

// PersistLastSignature stores last signatures persistently
func (p *ExtendedProtocol) PersistLastSignature(id uuid.UUID) error {
	if p.DB != nil {
		return p.DB.PersistLastSignature(id.String(), p.Signatures[id])
	} else {
		return p.saveFile(p.Signatures, p.Path+ContextSignaturesFile)
	}
}

func (p *ExtendedProtocol) loadFile(file string, v interface{}) error { // todo v map[string]interface{}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, v)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return p.loadFile(file+".bck", v)
		}
	}
	return nil
}

func (p *ExtendedProtocol) saveFile(v interface{}, file string) error { // todo v map[string]interface{}
	err := os.Rename(file, file+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}
	contextBytes, _ := json.MarshalIndent(v, "", "  ")
	return ioutil.WriteFile(file, contextBytes, 444)
}

// Value lets the struct implement the driver.Valuer interface. This method
// simply returns the JSON-encoded representation of the struct.
func (p ExtendedProtocol) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan lets the struct implement the sql.Scanner interface. This method
// simply decodes a JSON-encoded value into the struct fields.
func (p *ExtendedProtocol) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(b, &p)
}
