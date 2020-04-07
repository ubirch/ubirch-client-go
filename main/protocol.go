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
	Certificates map[uuid.UUID]SignedKeyRegistration
	DB           Database // todo make this an interface
	ContextFile  string
}

func (p *ExtendedProtocol) Init(dsn string) error {
	if dsn == "" {
		return nil
	}

	// use the database
	db, err := NewPostgres(dsn)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %v", err)
	}
	p.DB = db
	return nil

}

// Save saves current ubirch-protocol context, storing keys and signatures
func (p *ExtendedProtocol) SaveContext() error {
	if p.DB != nil {
		return p.DB.SetProtocolContext(p)
	} else {
		return p.saveFile(p.ContextFile)
	}
}

// PersistLastSignature stores last signatures persistently
func (p *ExtendedProtocol) PersistLastSignature(id uuid.UUID) error {
	if p.DB != nil {
		return p.DB.PersistLastSignature(id.String(), p.Signatures[id])
	} else {
		return p.saveFile(p.ContextFile)
	}
}

// PersistKey stores keys persistently
func (p *ExtendedProtocol) PersistKeystore() error {
	if p.DB != nil {
		return p.DB.PersistKeystore(p.GetKeystorer())
	} else {
		return p.saveFile(p.ContextFile)
	}
}

// loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) LoadContext() error {
	if p.DB != nil {
		return p.DB.GetProtocolContext(p)
	} else {
		return p.loadFile(p.ContextFile)
	}
}

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
