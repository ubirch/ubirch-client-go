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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName       = "keys.json"
	SignatureFileName = "signatures.json"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	db                 Database
	contextFile_Legacy string
}

// Init sets keys in crypto context and updates keystore in persistent storage
func (p *ExtendedProtocol) Init(configDir string, filename string, dsn string) error {
	// check if we want to use a database as persistent storage
	if dsn != "" {
		// FIXME // use the database
		//db, err := NewPostgres(dsn)
		//if err != nil {
		//	return fmt.Errorf("unable to connect to database: %v", err)
		//}
		//p.db = db
		//log.Printf("protocol context will be saved to database")
		log.Fatalf("database not supported in current version")
	} else if filename != "" {
		p.contextFile_Legacy = filepath.Join(configDir, filename)
		log.Printf("protocol context will be saved to files")
	} else {
		return fmt.Errorf("neither DSN nor filename for protocol context set")
	}

	err := p.portLegacyProtocolCtxFile()
	if err != nil {
		return err
	}

	err = p.LoadKeys()
	if err != nil {
		return err
	}

	err = p.LoadSignatures()
	if err != nil {
		return err
	}

	if len(p.Signatures) != 0 {
		log.Printf("loaded existing protocol context: %d signatures", len(p.Signatures))
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

func (p *ExtendedProtocol) LoadKeys() error {
	return loadFile(keyFileName, &p.Crypto) // todo filepath.Join(configDir, filename)
}

func (p *ExtendedProtocol) PersistKeys() error {
	return persistFile(keyFileName, &p.Crypto) // todo filepath.Join(configDir, filename)
}

func (p *ExtendedProtocol) LoadSignatures() error {
	return loadFile(SignatureFileName, &p.Signatures) // todo filepath.Join(configDir, filename)
}

func (p *ExtendedProtocol) PersistSignatures() error {
	return persistFile(SignatureFileName, &p.Signatures) // todo filepath.Join(configDir, filename)
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

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(source, "", "  ")
	return ioutil.WriteFile(file, contextBytes, 444)
}

func loadFile(file string, dest interface{}) error {
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
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return loadFile(file+".bck", dest)
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
