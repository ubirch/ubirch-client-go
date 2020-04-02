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
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"io/ioutil"
	"log"
	"os"
)

// configuration of the device
type Config struct {
	KeyService    string `json:"keyService"`
	VerifyService string `json:"verifyService"`
	Niomon        string `json:"niomon"`
	DSN           string `json:"dsn"`
	Secret        []byte // Secret is used to encrypt the key store
}

func (c *Config) Load(filename string) error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_DSN env variable set.
	if os.Getenv("UBIRCH_DSN") != "" {
		err := c.LoadEnv()
		if err != nil {
			return err
		}
		// check for validity
		if len(c.Secret) != 16 {
			return fmt.Errorf("Secret length must be 16 bytes (is %d)", len(c.Secret))
		}
		return nil
	}

	log.Println("loading config from file " + filename)
	return c.LoadFile(filename)
}

// LoadEnv reads the configuration from environment variables
func (c *Config) LoadEnv() error {
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) LoadFile(filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(contextBytes, c)
}

// LoadAuth loads the auth map from the environment or file
func LoadAuth(filename string) (map[string]string, error) {
	var err error
	authTokens := os.Getenv("UBIRCH_AUTH_MAP")
	authTokensBytes := []byte(authTokens)
	if authTokens == "" {
		log.Println("loading auth from file " + filename)
		authTokensBytes, err = ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
	}

	buffer := make(map[string][]string)
	err = json.Unmarshal(authTokensBytes, &buffer)
	if err != nil {
		return nil, err
	}

	authMap := make(map[string]string)
	for k, v := range buffer {
		authMap[k] = v[1]
	}
	return authMap, nil
}

// LoadKeys loads the keys map from the environment or file
func LoadKeys(filename string) (map[string]string, error) {
	var err error
	authTokens := os.Getenv("UBIRCH_AUTH_MAP")
	authTokensBytes := []byte(authTokens)
	if authTokens == "" {
		log.Println("loading keys from file " + filename)
		authTokensBytes, err = ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
	}

	buffer := make(map[string][]string)
	err = json.Unmarshal(authTokensBytes, &buffer)
	if err != nil {
		return nil, err
	}

	keysMap := make(map[string]string)
	for k, v := range buffer {
		keysMap[k] = v[0]
	}
	return keysMap, nil
}
