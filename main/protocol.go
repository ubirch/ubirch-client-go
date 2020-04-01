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
}

// saves current ubirch-protocol context, storing keys and signatures
func (p *ExtendedProtocol) save(file string) error {
	err := os.Rename(file, file+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}

	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	err = ioutil.WriteFile(file, contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

// saves current ubirch-protocol context, storing keys and signatures
func (p *ExtendedProtocol) saveDB(db Database) error {
	if db == nil {
		return fmt.Errorf("Database not set")
	}
	err := db.SetProtocolContext(p)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	}

	log.Printf("saved protocol context")
	return nil
}

func (p *ExtendedProtocol) read(contextBytes []byte) error {
	err := json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Printf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		log.Printf("%d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))
		return nil
	}
}

// loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) load(file string) error {
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = p.read(contextBytes)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			err = p.load(file + ".bck")
			if err != nil {
				return err
			}
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
