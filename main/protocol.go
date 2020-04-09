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
	Certificates map[string][]byte
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

	log.Printf("loaded %d keys from whitelist\n", len(keys))

	// update keystore in persistent storage // todo is this even necessary? test if it will overwrite existing keys!
	err = p.PersistContext()
	if err != nil {
		log.Printf("unable to store key pairs: %v\n", err)
	}

	return nil
}

// PersistContext saves current ubirch-protocol context, storing keystore, key certificates and signatures
func (p *ExtendedProtocol) PersistContext() error {
	if p.DB != nil {
		return p.DB.SetProtocolContext(p)
	} else {
		return p.saveFile(p.Path + ContextFile)
	}
}

// LoadContext loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) LoadContext() error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.Path + ContextFile)
	}
}

//// PersistLastSignature stores a devices last signature persistently
//func (p *ExtendedProtocol) PersistLastSignature(id uuid.UUID) error {
//	if p.DB != nil {
//		// todo return p.DB.PersistLastSignature(id.String(), p.Signatures[id])
//	} else {
//		return p.saveFile(p.Path + ContextFile)
//	}
//}
//
//// LoadLastSignature loads a devices last signatures from the persistent storage
//func (p *ExtendedProtocol) LoadLastSignature(id uuid.UUID) error {
//	if p.DB != nil {
//		// todo return p.DB.LoadLastSignature(id.String())
//	} else {
//		return p.loadFile(p.Path + ContextFile)
//	}
//}

func (p *ExtendedProtocol) saveFile(file string) error {
	err := os.Rename(file, file+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}
	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	return ioutil.WriteFile(file, contextBytes, 444)
}

func (p *ExtendedProtocol) loadFile(file string) error {
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, p)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return p.loadFile(file + ".bck")
		}
	}
	return nil
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
