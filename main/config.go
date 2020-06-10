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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	PROD_STAGE = "prod"

	keyURL      = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	identityURL = "https://identity.%s.ubirch.com/api/certs/v1/csr/register"
	niomonURL   = "https://niomon.%s.ubirch.com/"
	verifyURL   = "https://verify.%s.ubirch.com/api/upp"

	authEnv  = "UBIRCH_AUTH_MAP" // {UUID: [key, token]}
	authFile = "auth.json"       // {UUID: [key, token]}

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"
)

// configuration of the device
type Config struct {
	Devices          map[string]string `json:"devices"`          // maps UUIDs to backend auth tokens
	Secret           string            `json:"secret"`           // secret used to encrypt the key store
	Env              string            `json:"env"`              // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	DSN              string            `json:"DSN"`              // "data source name" for database connection
	StaticKeys       bool              `json:"staticKeys"`       // disable dynamic key generation, defaults to 'false'
	Keys             map[string]string `json:"keys"`             // maps UUIDs to injected keys
	CSR_Country      string            `json:"CSR_country"`      // subject country for public key Certificate Signing Requests
	CSR_Organization string            `json:"CSR_organization"` // subject organization for public key Certificate Signing Requests
	TLS              bool              `json:"TLS"`              // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile     string            `json:"TLSCertFile"`      // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile      string            `json:"TLSKeyFile"`       // filename of TLS key file name, defaults to "key.pem"
	CORS             bool              `json:"CORS"`             // enable CORS, defaults to false
	CORS_Origins     []string          `json:"CORS_origins"`     // list of allowed origin hosts, defaults to ["*"]
	Debug            bool              `json:"debug"`            // enable extended debug output, defaults to 'false'
	SecretBytes      []byte            // the decoded key store secret
	KeyService       string            // key service URL (set automatically)
	IdentityService  string            // identity service URL (set automatically)
	Niomon           string            // authentication service URL (set automatically)
	VerifyService    string            // verification service URL (set automatically)
}

func (c *Config) Load(configDir string, filename string) error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filepath.Join(configDir, filename))
	}
	if err != nil {
		return err
	}

	c.SecretBytes, err = base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.Secret, err)
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	_ = c.loadAuthMap(configDir)
	err = c.checkMandatory()
	if err != nil {
		return err
	}
	c.setDefaultCSR()
	c.setDefaultTLS(configDir)
	c.setDefaultCORS()
	return c.setDefaultURLs()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Print("loading configuration from environment variables")
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
	if c.Devices == nil || len(c.Devices) == 0 {
		return fmt.Errorf("There are no devices authorized to use this client.\n" +
			"It is mandatory to set at least one device UUID and auth token in the configuration.\n" +
			"For more information take a look at the README under 'Configuration'.")
	} else {
		log.Printf("%d known UUID(s)", len(c.Devices))
		for name := range c.Devices {
			log.Debugf(" - %s", name)
		}
	}

	if len(c.SecretBytes) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.SecretBytes))
	}

	if c.StaticKeys && (c.Keys == nil || len(c.Keys) == 0) {
		return fmt.Errorf("dynamic key generation disabled but no injected signing keys found in configuration")
	}

	return nil
}

func (c *Config) setDefaultCSR() {
	if c.CSR_Country == "" {
		c.CSR_Country = "DE"
	}

	if c.CSR_Organization == "" {
		c.CSR_Organization = "ubirch GmbH"
	}
}

func (c *Config) setDefaultTLS(configDir string) {
	if c.TLS {
		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(configDir, c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(configDir, c.TLS_KeyFile)
	}
}

func (c *Config) setDefaultCORS() {
	if c.CORS {
		if c.CORS_Origins == nil {
			c.CORS_Origins = []string{"*"} // allow all origins
		}
	}
}

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(niomonURL, c.Env)
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.Niomon, ".")[1]

	// assert Env variable value is a valid UBIRCH backend environment
	if !(c.Env == DEV_STAGE || c.Env == DEMO_STAGE || c.Env == PROD_STAGE) {
		return fmt.Errorf("invalid UBIRCH backend environment: \"%s\"", c.Env)
	}

	log.Printf("UBIRCH backend \"%s\" environment", c.Env)

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(keyURL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	if c.IdentityService == "" {
		c.IdentityService = fmt.Sprintf(identityURL, c.Env)
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(verifyURL, c.Env)
	}
	return nil
}

// loadAuthMap loads the auth map from the environment
func (c *Config) loadAuthMap(configDir string) error {
	var err error
	var authMapBytes []byte

	authMap := os.Getenv(authEnv)
	if authMap != "" {
		authMapBytes = []byte(authMap)
	} else {
		authMapBytes, err = ioutil.ReadFile(filepath.Join(configDir, authFile))
		if err != nil {
			return err
		}
	}

	buffer := make(map[string][]string)
	err = json.Unmarshal(authMapBytes, &buffer)
	if err != nil {
		return err
	}

	if c.Keys == nil {
		c.Keys = make(map[string]string)
	}

	if c.Devices == nil {
		c.Devices = make(map[string]string)
	}

	for k, v := range buffer {
		c.Keys[k] = v[0]
		c.Devices[k] = v[1]
	}

	return nil
}
