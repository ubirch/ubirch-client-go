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
	"io/ioutil"
	"log"
	"os"

	"github.com/kelseyhightower/envconfig"
)

// configuration of the device
type Config struct {
	Auth          string `json:"auth"`
	Password      string `json:"password"`
	KeyService    string `json:"keyService"`
	VerifyService string `json:"verifyService"`
	Niomon        string `json:"niomon"`
	Data          string `json:"data"`
	Interface     struct {
		RxCert   string `json:"rxCert"`
		RxVerify string `json:"rxVerify"`
		TxVerify string `json:"txVerify"`
	}
	DSN string `json:"dsn"`

	// Secret is used to encrypt the key store
	Secret []byte
}

func (c *Config) Load(filename string) error {
	if err := c.LoadEnv(); err == nil && os.Getenv("UBIRCH_PASSWORD") != "" {
		// check for validity
		if len(c.Secret) != 16 {
			log.Fatalf("Secret length must be 16 bytes (is %d)", len(c.Secret))
		}

		return nil
	}

	err := c.LoadFile(filename)
	if err != nil {
		fmt.Println("ERROR: unable to read configuration: ", err)
		fmt.Println("ERROR: a configuration file is required to run the client")
		fmt.Println()
		fmt.Println("Follow these steps to configure this client:")
		fmt.Println("  1. visit https://console.demo.ubirch.com and register a user")
		fmt.Println("  2. register a new device and save the device configuration in " + filename)
		fmt.Println("  3. restart the client")
	}

	return err
}

// LoadEnv reads the configuration from environment variables
func (c *Config) LoadEnv() error {
	err := envconfig.Process("ubirch", c)
	return err
}

// LoadFile reads the configuration from a json file
func (c *Config) LoadFile(filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, c)
	if err != nil {
		log.Fatalf("unable to read configuration %v", err)
		return err
	}

	log.Printf("configuration found")
	if c.Auth == "" {
		c.Auth = "ubirch"
	}
	return nil
}

// LoadAuth loads the auth map from the environment.
func LoadAuth() (map[string]string, error) {
	authTokens := os.Getenv("UBIRCH_AUTH_MAP")

	buffer := make(map[string][]string)
	err := json.Unmarshal([]byte(authTokens), &buffer)
	if err != nil {
		return nil, err
	}

	authMap := make(map[string]string)
	for k, v := range buffer {
		authMap[k] = v[1]
	}
	return authMap, nil
}

// LoadKeys loads the keys map from the environment.
func LoadKeys() (map[string]string, error) {
	authTokens := os.Getenv("UBIRCH_AUTH_MAP")

	buffer := make(map[string][]string)
	err := json.Unmarshal([]byte(authTokens), &buffer)
	if err != nil {
		return nil, err
	}

	keysMap := make(map[string]string)
	for k, v := range buffer {
		keysMap[k] = v[0]
	}
	return keysMap, nil
}
