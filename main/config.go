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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

const (
	KEY_URL    = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	NIOMON_URL = "https://niomon.%s.ubirch.com/"
	VERIFY_URL = "https://verify.%s.ubirch.com/api/upp"
)

// configuration of the device
type Config struct {
	Devices       map[string]string `json:"devices"`       // maps UUIDs to backend auth tokens
	Secret        base64string      `json:"secret"`        // secret used to encrypt the key store
	DSN           string            `json:"dsn"`           // "data source name" for database connection
	StaticUUID    bool              `json:"staticUUID"`    // only accept requests from UUIDs with injected signing key. default: false -> dynamic key generation
	Env           string            `json:"env"`           // the ubirch backend environment [dev, demo, prod]
	KeyService    string            `json:"keyService"`    // key service URL (set automatically)
	Niomon        string            `json:"niomon"`        // authentication service URL (set automatically)
	VerifyService string            `json:"verifyService"` // verification service URL (set automatically)
}

type base64string []byte

// Set implements the envconf.Setter by translating the base64 encrypted env
// variable into a byte slice.
func (b base64string) Set(value string) error {
	var err error
	b, err = base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) Load() error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_DEVICES env variable set.
	var err error
	if os.Getenv("UBIRCH_DEVICES") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(Path + ConfigFile)
	}
	if err != nil {
		return err
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	c.setDefaultURLs()
	return nil
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Println("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	log.Printf("loading configuration from file (%s)", filename)
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(contextBytes, c)
}

func (c *Config) checkMandatory() error {
	if c.Devices == nil {
		return fmt.Errorf("no passwords set in config")
	}
	if len(c.Secret) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.Secret))
	}
	return nil
}

func (c *Config) setDefaultURLs() {
	if c.Env == "" {
		c.Env = "prod"
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(KEY_URL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.KeyService, ".")[1]

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(NIOMON_URL, c.Env)
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(VERIFY_URL, c.Env)
	}
}

// LoadKeys loads the keys map from environment or file
func LoadKeys() (map[string]string, error) {
	var err error
	var keyBytes []byte

	keys := os.Getenv("UBIRCH_KEY_MAP")
	if keys != "" {
		keyBytes = []byte(keys)
	} else {
		keyBytes, err = ioutil.ReadFile(Path + KeyFile)
		if err != nil {
			return nil, err
		}
	}

	keyMap := make(map[string]string)
	err = json.Unmarshal(keyBytes, &keyMap)
	return keyMap, err
}
