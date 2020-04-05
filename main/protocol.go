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
	"encoding/json"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[uuid.UUID]SignedKeyRegistration
	ContextFile  string
}

// saves current ubirch-protocol context, storing keys and signatures
func (p *ExtendedProtocol) SaveContext() error {
	err := os.Rename(p.ContextFile, p.ContextFile+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}
	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	return ioutil.WriteFile(p.ContextFile, contextBytes, 444)
}

// loads current ubirch-protocol context, loading keys and signatures
func (p *ExtendedProtocol) LoadContext() error {
	return p.recursiveLoad(p.ContextFile)
}

func (p *ExtendedProtocol) recursiveLoad(file string) error {
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
			return p.recursiveLoad(file + ".bck")
		}
	}
	return nil
}
