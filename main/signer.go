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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var genericError = HTTPResponse{
	Code:    http.StatusInternalServerError,
	Header:  make(map[string][]string),
	Content: []byte(http.StatusText(http.StatusInternalServerError)),
}

type SignerMessage interface {
	GetUUID() uuid.UUID
	GetMessage() []byte
	GetAuthToken() string
}

type Signer struct {
	*sync.Mutex
	conf            Config
	protocol        *ExtendedProtocol
	DB              Database
	keyMap          map[string]string // todo i think we can get rid of the key map and just generate keys here
	registeredUUIDs map[uuid.UUID]bool
}

func (s *Signer) Sign(msg SignerMessage) HTTPResponse {
	s.Lock()
	defer s.Unlock()

	uid := msg.GetUUID()
	if uid == uuid.Nil {
		log.Printf("warning: UUID not parsable")
	}

	name := uid.String()
	_, err := s.protocol.Crypto.GetPublicKey(name)
	if err != nil {
		// retrieve a signing key from keys map, since it doesnt exist in protocol instance yet
		// if there is no signing key for this uuid in the key map return error
		if s.keyMap[name] == "" {
			return genericError
		}

		// set private key (public key will automatically be calculated and set)
		keyBytes, err := base64.StdEncoding.DecodeString(s.keyMap[name])
		if err != nil {
			log.Printf("Error decoding private key string for %s: %v, string was: %s", name, err, keyBytes)
			return genericError
		}
		err = s.protocol.Crypto.SetKey(name, uid, keyBytes)
		if err != nil {
			log.Printf("Error inserting private key: %v,", err)
			return genericError
		}
	}

	// check if public key is registered at the key service
	_, registered := s.registeredUUIDs[uid]
	if !registered {
		cert, err := getSignedCertificate(s.protocol, name, uid)
		if err != nil {
			log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
			return genericError
		}
		log.Printf("CERT [%s]\n", cert)

		_, _, resp, err := post(cert, s.conf.KeyService, map[string]string{"Content-Type": "application/json"}) // todo handle response code
		if err != nil {
			log.Printf("%s: unable to register public key: %v\n", name, err)
			return genericError
		}
		log.Printf("%s: registered key: (%d) %v", name, len(resp), string(resp))
		s.registeredUUIDs[uid] = true
	}

	// send UPP (hash)
	hash := sha256.Sum256(msg.GetMessage())
	log.Printf("%s: hash %s (%s)\n", name,
		base64.StdEncoding.EncodeToString(hash[:]),
		hex.EncodeToString(hash[:]))

	upp, err := s.protocol.Sign(name, hash[:], ubirch.Chained)
	if err != nil {
		log.Printf("%s: unable to create UPP: %v\n", name, err)
		return genericError
	}
	log.Printf("%s: UPP %s\n", name, hex.EncodeToString(upp))

	// save state for every message
	if s.DB == nil {
		log.Fatalf("Database not specified and File not supported")
	}

	err = s.protocol.saveDB(s.DB)
	if err != nil {
		log.Printf("unable to save p context in database: %v", err)
	}

	// post UPP to ubirch backend
	code, header, resp, err := post(upp, s.conf.Niomon, map[string]string{
		"x-ubirch-hardware-id": name,
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(msg.GetAuthToken())),
	})
	if err != nil {
		log.Printf("%s: send failed: %q\n", name, resp)
		return genericError
	}
	log.Printf("%s: %q\n", name, resp)

	return HTTPResponse{Code: code, Header: header, Content: resp}
}
