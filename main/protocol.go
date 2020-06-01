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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[string][]byte
	db           Database
	contextFile  string
}

// INIT sets keys in crypto context and automatically updates keystore in persistent storage
func (p *ExtendedProtocol) Init(configDir string, filename string, dsn string, keys map[string]string) error {
	// check if we want to use a database as persistent storage
	if dsn != "" {
		// use the database
		db, err := NewPostgres(dsn)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		p.db = db
		log.Printf("protocol context will be saved to database")
	} else {
		p.contextFile = filepath.Join(configDir, filename)
		log.Printf("protocol context will be saved to file (%s)", p.contextFile)
	}

	// try to read an existing protocol context from persistent storage (keystore, last signatures, key certificates)
	err := p.LoadContext()
	if err != nil {
		return fmt.Errorf("unable to load protocol context: %v", err)
	}
	log.Printf("loaded protocol context: %d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))

	if keys != nil {
		// inject keys from configuration to keystore
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

		log.Printf("injected %d keys from configuration to keystore\n", len(keys))

		// update keystore in persistent storage
		err = p.PersistContext()
		if err != nil {
			return fmt.Errorf("unable to store key pairs: %v\n", err)
		}
	}
	return nil
}

func (p *ExtendedProtocol) Deinit() error {
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			return fmt.Errorf("unable to close database connection: %v", err)
		}
	}
	return nil
}

// PersistContext saves current ubirch-protocol context, storing keystore, key certificates and signatures
func (p *ExtendedProtocol) PersistContext() error {
	if p.db != nil {
		return p.db.SetProtocolContext(p)
	} else {
		return p.saveFile(p.contextFile)
	}
}

// LoadContext loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) LoadContext() error {
	if p.db != nil {
		return p.db.GetProtocolContext(p)
	} else {
		return p.loadFile(p.contextFile)
	}
}

func (p *ExtendedProtocol) saveFile(file string) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Printf("WARNING: unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	return ioutil.WriteFile(file, contextBytes, 444)
}

func (p *ExtendedProtocol) loadFile(file string) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
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
