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

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength32 = 32

	DEV_STAGE  = "dev"
	DEMO_STAGE = "demo"
	PROD_STAGE = "prod"

	defaultKeyURL      = "https://identity.%s.ubirch.com/api/keyService/v1/pubkey"
	defaultIdentityURL = "https://identity.%s.ubirch.com/api/certs/v1/csr/register"
	defaultNiomonURL   = "https://niomon.%s.ubirch.com/"
	defaultVerifyURL   = "https://verify.%s.ubirch.com/api/upp/verify"

	identitiesFileName = "identities.json" // [{ "uuid": "<uuid>", "password": "<auth>" }]

	defaultCSRCountry      = "DE"
	defaultCSROrganization = "ubirch GmbH"

	defaultTCPAddr = ":8080"

	defaultTLSCertFile = "cert.pem"
	defaultTLSKeyFile  = "key.pem"

	defaultKeyDerivationParamMemory      = 15
	defaultKeyDerivationParamTime        = 2
	defaultKeyDerivationParamParallelism = 1
	defaultKeyDerivationKeyLen           = 32
	defaultKeyDerivationSaltLen          = 16
)

var IsDevelopment bool

type Config struct {
	Devices            map[string]string `json:"devices"`                                             // maps UUIDs to backend auth tokens
	Secret16Base64     string            `json:"secret" envconfig:"secret"`                           // LEGACY: 16 bytes secret used to encrypt the key store (mandatory only for migration)
	Secret32Base64     string            `json:"secret32" envconfig:"secret32"`                       // 32 byte secret used to encrypt the key store (mandatory)
	RegisterAuth       string            `json:"registerAuth"`                                        // auth token needed for new identity registration
	Env                string            `json:"env"`                                                 // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	PostgresDSN        string            `json:"postgresDSN" envconfig:"POSTGRES_DSN"`                // data source name for postgres database
	SqliteDSN          string            `json:"sqliteDSN" envconfig:"SQLITE_DSN"`                    // path to the sqlite db file
	DbMaxConns         int               `json:"dbMaxConns" envconfig:"DB_MAX_CONNS"`                 // maximum number of open connections to the database
	TCP_addr           string            `json:"TCP_addr"`                                            // the TCP address for the server to listen on, in the form "host:port", defaults to ":8080"
	TLS                bool              `json:"TLS"`                                                 // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile       string            `json:"TLSCertFile"`                                         // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile        string            `json:"TLSKeyFile"`                                          // filename of TLS key file name, defaults to "key.pem"
	CORS               bool              `json:"CORS"`                                                // enable CORS, defaults to 'false'
	CORS_Origins       []string          `json:"CORS_origins"`                                        // list of allowed origin hosts, defaults to ["*"]
	CSR_Country        string            `json:"CSR_country"`                                         // subject country for public key Certificate Signing Requests
	CSR_Organization   string            `json:"CSR_organization"`                                    // subject organization for public key Certificate Signing Requests
	Debug              bool              `json:"debug"`                                               // enable extended debug output, defaults to 'false'
	LogTextFormat      bool              `json:"logTextFormat"`                                       // log in text format for better human readability, default format is JSON
	KdMaxTotalMemMiB   uint32            `json:"kdMaxTotalMemMiB" envconfig:"KD_MAX_TOTAL_MEM_MIB"`   // maximal total memory to use for key derivation at a time in MiB
	KdParamMemMiB      uint32            `json:"kdParamMemMiB" envconfig:"KD_PARAM_MEM_MIB"`          // memory parameter for key derivation, specifies the size of the memory in MiB
	KdParamTime        uint32            `json:"kdParamTime" envconfig:"KD_PARAM_TIME"`               // time parameter for key derivation, specifies the number of passes over the memory
	KdParamParallelism uint8             `json:"kdParamParallelism" envconfig:"KD_PARAM_PARALLELISM"` // parallelism (threads) parameter for key derivation, specifies the number of threads and can be adjusted to the number of available CPUs
	KdParamKeyLen      uint32            `json:"kdParamKeyLen" envconfig:"KD_PARAM_KEY_LEN"`          // key length parameter for key derivation, specifies the length of the resulting key in bytes
	KdParamSaltLen     uint32            `json:"kdParamSaltLen" envconfig:"KD_PARAM_SALT_LEN"`        // salt length parameter for key derivation, specifies the length of the random salt in bytes
	KdUpdateParams     bool              `json:"kdUpdateParams" envconfig:"KD_UPDATE_PARAMS"`         // update key derivation parameters of already existing password hashes
	KeyService         string            // key service URL (set automatically)
	IdentityService    string            // identity service URL (set automatically)
	Niomon             string            // authentication service URL (set automatically)
	VerifyService      string            // verification service URL (set automatically)
	SecretBytes32      []byte            // the decoded 32 byte key store secret for database (set automatically)
	ConfigDir          string            // path to config file (set automatically)
}

func (c *Config) Load(configDir, filename string) error {
	// assume that we want to load from env instead of config files, if
	// we have the UBIRCH_SECRET env variable set.
	var err error
	if os.Getenv("UBIRCH_SECRET32") != "" {
		err = c.loadEnv()
	} else {
		err = c.loadFile(filepath.Join(configDir, filename))
	}
	if err != nil {
		return err
	}

	c.SecretBytes32, err = base64.StdEncoding.DecodeString(c.Secret32Base64)
	if err != nil {
		return fmt.Errorf("unable to decode base64 encoded secret (%s): %v", c.Secret32Base64, err)
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.LogTextFormat {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	}

	c.ConfigDir = configDir

	err = c.loadIdentitiesFile()
	if err != nil {
		return err
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	// set defaults
	c.setDefaultCSR()
	c.setDefaultTLS()
	c.setDefaultCORS()
	c.setKeyDerivationParams()
	return c.setDefaultURLs()
}

// loadEnv reads the configuration from environment variables
func (c *Config) loadEnv() error {
	log.Infof("loading configuration from environment variables")
	return envconfig.Process("ubirch", c)
}

// LoadFile reads the configuration from a json file
func (c *Config) loadFile(filename string) error {
	log.Infof("loading configuration from file: %s", filename)

	fileHandle, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}

	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			log.Error(fileCloseErr)
		}
		return err
	}

	return fileHandle.Close()
}

func (c *Config) checkMandatory() error {
	if len(c.SecretBytes32) != secretLength32 {
		return fmt.Errorf("secret for aes-256 key encryption ('secret32' / 'UBIRCH_SECRET32') length must be %d bytes (is %d)", secretLength32, len(c.SecretBytes32))
	}

	if len(c.RegisterAuth) == 0 {
		return fmt.Errorf("missing 'registerAuth' / 'UBIRCH_REGISTERAUTH' in configuration")
	}

	return nil
}

func (c *Config) setDefaultCSR() {
	if c.CSR_Country == "" {
		c.CSR_Country = defaultCSRCountry
	}
	log.Debugf("CSR Subject Country: %s", c.CSR_Country)

	if c.CSR_Organization == "" {
		c.CSR_Organization = defaultCSROrganization
	}
	log.Debugf("CSR Subject Organization: %s", c.CSR_Organization)
}

func (c *Config) setDefaultTLS() {
	if c.TCP_addr == "" {
		c.TCP_addr = defaultTCPAddr
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(c.ConfigDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(c.ConfigDir, c.TLS_KeyFile)
		log.Debugf(" -  Key: %s", c.TLS_KeyFile)
	}
}

func (c *Config) setDefaultCORS() {
	if c.CORS {
		log.Debug("CORS enabled")

		if c.CORS_Origins == nil {
			c.CORS_Origins = []string{"*"} // allow all origins
		}
		log.Debugf(" - Allowed Origins: %v", c.CORS_Origins)
	}
}

func (c *Config) setKeyDerivationParams() {
	if c.KdParamMemMiB == 0 {
		c.KdParamMemMiB = defaultKeyDerivationParamMemory
	}

	if c.KdParamTime == 0 {
		c.KdParamTime = defaultKeyDerivationParamTime
	}

	if c.KdParamParallelism == 0 {
		c.KdParamParallelism = defaultKeyDerivationParamParallelism
	}

	if c.KdParamKeyLen == 0 {
		c.KdParamKeyLen = defaultKeyDerivationKeyLen
	}

	if c.KdParamSaltLen == 0 {
		c.KdParamSaltLen = defaultKeyDerivationSaltLen
	}
}

func (c *Config) setDefaultURLs() error {
	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	// set flag for non-production environments
	if c.Env == DEV_STAGE || c.Env == DEMO_STAGE {
		IsDevelopment = true
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(defaultKeyURL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	if c.IdentityService == "" {
		c.IdentityService = fmt.Sprintf(defaultIdentityURL, c.Env)
	}

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(defaultNiomonURL, c.Env)
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(defaultVerifyURL, c.Env)
	}

	log.Infof("UBIRCH backend environment: %s", c.Env)
	log.Debugf(" - Key Service:            %s", c.KeyService)
	log.Debugf(" - Identity Service:       %s", c.IdentityService)
	log.Debugf(" - Authentication Service: %s", c.Niomon)
	log.Debugf(" - Verification Service:   %s", c.VerifyService)

	return nil
}

// loadIdentitiesFile loads device identities from the identities JSON file.
// Returns without error if file does not exist.
func (c *Config) loadIdentitiesFile() error {
	identitiesFile := filepath.Join(c.ConfigDir, identitiesFileName)

	// if file does not exist, return right away
	if _, err := os.Stat(identitiesFile); os.IsNotExist(err) {
		return nil
	}

	fileHandle, err := os.Open(filepath.Clean(identitiesFile))
	if err != nil {
		return err
	}

	var identities []map[string]string

	err = json.NewDecoder(fileHandle).Decode(&identities)
	if err != nil {
		if fileCloseErr := fileHandle.Close(); fileCloseErr != nil {
			log.Error(fileCloseErr)
		}
		return err
	}

	err = fileHandle.Close()
	if err != nil {
		return err
	}

	if c.Devices == nil {
		c.Devices = make(map[string]string, len(identities))
	}

	for _, identity := range identities {
		c.Devices[identity["uuid"]] = identity["password"]
	}

	return nil
}
