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
	"io/ioutil"
	"log"
)

// configuration of the device
type Config struct {
	Auth       string `json:"auth"`
	Password   string `json:"password"`
	KeyService string `json:"keyService"`
	Niomon     string `json:"niomon"`
	Data       string `json:"data"`
	Mqtt       struct {
		Address  string `json:"address"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
}

// read the configuration
func (c *Config) Load(filename string) error {
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
