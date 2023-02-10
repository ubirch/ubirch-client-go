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

	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"

	log "github.com/sirupsen/logrus"
)

const (
	secretLength32 = 32

	DEV_STAGE        = "dev"
	DEV_UUID         = "9d3c78ff-22f3-4441-a5d1-85c636d486ff"
	DEV_PUBKEY_ECDSA = "LnU8BkvGcZQPy5gWVUL+PHA0DP9dU61H8DBO8hZvTyI7lXIlG1/oruVMT7gS2nlZDK9QG+ugkRt/zTrdLrAYDA=="

	DEMO_STAGE        = "demo"
	DEMO_UUID         = "07104235-1892-4020-9042-00003c94b60b"
	DEMO_PUBKEY_ECDSA = "xm+iIomBRjR3QdvLJrGE1OBs3bAf8EI49FfgBriRk36n4RUYX+0smrYK8tZkl6Lhrt9lzjiUGrXGijRoVE+UjA=="

	PROD_STAGE        = "prod"
	PROD_UUID         = "10b2e1a4-56b3-4fff-9ada-cc8c20f93016"
	PROD_PUBKEY_ECDSA = "pJdYoJN0N3QTFMBVjZVQie1hhgumQVTy2kX9I7kXjSyoIl40EOa9MX24SBAABBV7xV2IFi1KWMnC1aLOIvOQjQ=="

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

	postgresDriver    = "postgres"
	sqliteDriver      = "sqlite"
	defaultSQLiteName = "sqlite.db"

	defaultKeyDerivationParamMemory      = 15
	defaultKeyDerivationParamTime        = 2
	defaultKeyDerivationParamParallelism = 1
	defaultKeyDerivationKeyLen           = 32
	defaultKeyDerivationSaltLen          = 16

	defaultIdentityServiceTimeoutMs = 10_000 // should be high since we want to avoid canceling an otherwise successful key registration
	defaultAuthServiceTimeoutMs     = 2_000
	defaultVerifyServiceTimeoutMs   = 600
	defaultVerificationTimeoutMs    = 2_000
)

var IsDevelopment bool

type Config struct {
	Devices                       map[string]string `json:"devices" envconfig:"DEVICES"`                                                 // maps UUIDs to backend auth tokens
	Secret16Base64                string            `json:"secret" envconfig:"SECRET"`                                                   // LEGACY: 16 bytes secret used to encrypt the key store (mandatory only for migration)
	Secret32Base64                string            `json:"secret32" envconfig:"SECRET32"`                                               // 32 byte secret used to encrypt the key store (mandatory)
	StaticAuth                    string            `json:"staticAuth" envconfig:"STATIC_AUTH"`                                          // static auth token needed for identity registration, csr creation or key deactivation
	EnableRegistrationEndpoint    bool              `json:"enableRegistrationEndpoint" envconfig:"ENABLE_REGISTRATION_ENDPOINT"`         // expose endpoint for identity registration
	EnableCSRCreationEndpoint     bool              `json:"enableCSRCreationEndpoint" envconfig:"ENABLE_CSR_CREATION_ENDPOINT"`          // expose endpoint for CSR creation
	EnableDeactivationEndpoint    bool              `json:"enableDeactivationEndpoint" envconfig:"ENABLE_DEACTIVATION_ENDPOINT"`         // expose endpoint for key status updates (de-/re-activation)
	Env                           string            `json:"env" envconfig:"ENV"`                                                         // the ubirch backend environment [dev, demo, prod], defaults to 'prod'
	DbDriver                      string            `json:"dbDriver" envconfig:"DB_DRIVER"`                                              // database driver name
	DbDSN                         string            `json:"dbDSN" envconfig:"DB_DSN"`                                                    // data source name for database, path to the sqlite db file
	DbMaxOpenConns                int               `json:"dbMaxOpenConns" envconfig:"DB_MAX_OPEN_CONNS"`                                // maximum number of open connections to the database
	DbMaxIdleConns                int               `json:"dbMaxIdleConns" envconfig:"DB_MAX_IDLE_CONNS"`                                // maximum number of connections in the idle connection pool
	DbConnMaxLifetimeSec          int64             `json:"dbConnMaxLifetimeSec" envconfig:"DB_CONN_MAX_LIFETIME_SEC"`                   // maximum amount of time in seconds a connection may be reused
	DbConnMaxIdleTimeSec          int64             `json:"dbConnMaxIdleTimeSec" envconfig:"DB_CONN_MAX_IDLE_TIME_SEC"`                  // maximum amount of time in seconds a connection may be idle
	TCP_addr                      string            `json:"TCP_addr" envconfig:"TCP_ADDR"`                                               // the TCP address for the server to listen on, in the form "host:port", defaults to ":8080"
	TLS                           bool              `json:"TLS" envconfig:"TLS"`                                                         // enable serving HTTPS endpoints, defaults to 'false'
	TLS_CertFile                  string            `json:"TLSCertFile" envconfig:"TLS_CERTFILE"`                                        // filename of TLS certificate file name, defaults to "cert.pem"
	TLS_KeyFile                   string            `json:"TLSKeyFile" envconfig:"TLS_KEYFILE"`                                          // filename of TLS key file name, defaults to "key.pem"
	CORS                          bool              `json:"CORS" envconfig:"CORS"`                                                       // enable CORS, defaults to 'false'
	CORS_Origins                  []string          `json:"CORS_origins" envconfig:"CORS_ORIGINS"`                                       // list of allowed origin hosts, defaults to ["*"]
	CSR_Country                   string            `json:"CSR_country" envconfig:"CSR_COUNTRY"`                                         // subject country for public key Certificate Signing Requests
	CSR_Organization              string            `json:"CSR_organization" envconfig:"CSR_ORGANIZATION"`                               // subject organization for public key Certificate Signing Requests
	Debug                         bool              `json:"debug" envconfig:"DEBUG"`                                                     // enable extended debug output, defaults to 'false'
	LogTextFormat                 bool              `json:"logTextFormat" envconfig:"LOGTEXTFORMAT"`                                     // log in text format for better human readability, default format is JSON
	LogKnownIdentities            bool              `json:"logKnownIdentities" envconfig:"LOG_KNOWN_IDENTITIES"`                         // log the UUIDs of all known identities at startup
	KdMaxTotalMemMiB              uint32            `json:"kdMaxTotalMemMiB" envconfig:"KD_MAX_TOTAL_MEM_MIB"`                           // maximal total memory to use for key derivation at a time in MiB
	KdParamMemMiB                 uint32            `json:"kdParamMemMiB" envconfig:"KD_PARAM_MEM_MIB"`                                  // memory parameter for key derivation, specifies the size of the memory in MiB
	KdParamTime                   uint32            `json:"kdParamTime" envconfig:"KD_PARAM_TIME"`                                       // time parameter for key derivation, specifies the number of passes over the memory
	KdParamParallelism            uint8             `json:"kdParamParallelism" envconfig:"KD_PARAM_PARALLELISM"`                         // parallelism (threads) parameter for key derivation, specifies the number of threads and can be adjusted to the number of available CPUs
	KdParamKeyLen                 uint32            `json:"kdParamKeyLen" envconfig:"KD_PARAM_KEY_LEN"`                                  // key length parameter for key derivation, specifies the length of the resulting key in bytes
	KdParamSaltLen                uint32            `json:"kdParamSaltLen" envconfig:"KD_PARAM_SALT_LEN"`                                // salt length parameter for key derivation, specifies the length of the random salt in bytes
	KdUpdateParams                bool              `json:"kdUpdateParams" envconfig:"KD_UPDATE_PARAMS"`                                 // update key derivation parameters of already existing password hashes
	IdentityServiceTimeoutMs      int64             `json:"identityServiceTimeoutMs" envconfig:"IDENTITY_SERVICE_TIMEOUT_MS"`            // time limit for requests to the ubirch identity service in milliseconds
	AuthServiceTimeoutMs          int64             `json:"authServiceTimeoutMs" envconfig:"AUTH_SERVICE_TIMEOUT_MS"`                    // time limit for requests to the ubirch authentication service (niomon) in milliseconds
	VerifyServiceTimeoutMs        int64             `json:"verifyServiceTimeoutMs" envconfig:"VERIFY_SERVICE_TIMEOUT_MS"`                // time limit for requests to the ubirch verification service in milliseconds
	VerificationTimeoutMs         int64             `json:"verificationTimeoutMs" envconfig:"VERIFICATION_TIMEOUT_MS"`                   // time limit for repeated attempts to verify a hash at the ubirch verification service in milliseconds
	VerifyFromKnownIdentitiesOnly bool              `json:"verifyFromKnownIdentitiesOnly" envconfig:"VERIFY_FROM_KNOWN_IDENTITIES_ONLY"` // flag to determine if a public key should be retrieved from the ubirch identity service in case of incoming verification request for UPP from unknown identity
	ServerIdentity                *identity         `json:"serverIdentity" envconfig:"SERVER_IDENTITY"`                                  // UUID and public keys of the backend for response signature verification
	KeyService                    string            // key service URL (set automatically)
	IdentityService               string            // identity service URL (set automatically)
	Niomon                        string            // authentication service URL (set automatically)
	VerifyService                 string            // verification service URL (set automatically)
	SecretBytes32                 []byte            // the decoded 32 byte key store secret for database (set automatically)
}

type identity struct {
	UUID   uuid.UUID
	PubKey []byte
}

var defaultServerIdentities = map[string]map[string]string{
	DEV_STAGE:  {"UUID": DEV_UUID, "PubKey": DEV_PUBKEY_ECDSA},
	DEMO_STAGE: {"UUID": DEMO_UUID, "PubKey": DEMO_PUBKEY_ECDSA},
	PROD_STAGE: {"UUID": PROD_UUID, "PubKey": PROD_PUBKEY_ECDSA},
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

	err = c.loadIdentitiesFile(configDir)
	if err != nil {
		return err
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	// set defaults
	c.setDefaultCSR()
	c.setDefaultTLS(configDir)
	c.setDefaultCORS()
	c.setDefaultSQLite(configDir)
	c.setKeyDerivationParams()
	c.setDefaultTimeouts()
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
	var missingConfig bool

	if len(c.SecretBytes32) != secretLength32 {
		missingConfig = true
		log.Errorf("secret for aes-256 key encryption ('secret32' / 'UBIRCH_SECRET32') length must be %d bytes (is %d)", secretLength32, len(c.SecretBytes32))
	}

	if len(c.DbDriver) == 0 {
		missingConfig = true
		log.Errorf("missing 'dbDriver' / 'UBIRCH_DB_DRIVER' in configuration (\"%s\" | \"%s\")", postgresDriver, sqliteDriver)
	} else if c.DbDriver != postgresDriver && c.DbDriver != sqliteDriver {
		missingConfig = true
		log.Errorf("invalid value for 'dbDriver' / 'UBIRCH_DB_DRIVER' in configuration: \"%s\", expected \"%s\" or \"%s\"", c.DbDriver, postgresDriver, sqliteDriver)
	} else if c.DbDriver == postgresDriver && len(c.DbDSN) == 0 {
		missingConfig = true
		log.Errorf("missing 'dbDSN' / 'UBIRCH_DB_DSN' for %s in configuration", c.DbDriver)
	}

	if (c.EnableRegistrationEndpoint || c.EnableCSRCreationEndpoint || c.EnableDeactivationEndpoint) &&
		len(c.StaticAuth) == 0 {
		missingConfig = true
		log.Errorf("missing 'staticAuth' / 'UBIRCH_STATIC_AUTH' in configuration")
	}

	if !c.EnableRegistrationEndpoint {
		log.Warnf("identity registration endpoint disabled. To enable, set json:\"enableRegistrationEndpoint\" env:\"UBIRCH_ENABLE_REGISTRATION_ENDPOINT\" =true")
	}

	if !c.EnableCSRCreationEndpoint {
		log.Warnf("CSR creation endpoint disabled. To enable, set json:\"enableCSRCreationEndpoint\" env:\"UBIRCH_ENABLE_CSR_CREATION_ENDPOINT\" =true")
	}

	if !c.EnableDeactivationEndpoint {
		log.Warnf("key deactivation endpoint disabled. To enable, set json:\"enableDeactivationEndpoint\" env:\"ENABLE_DEACTIVATION_ENDPOINT\" =true")
	}

	if missingConfig {
		return fmt.Errorf("missing mandatory configuration")
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

func (c *Config) setDefaultTLS(configDir string) {
	if c.TCP_addr == "" {
		c.TCP_addr = defaultTCPAddr
	}
	log.Debugf("TCP address: %s", c.TCP_addr)

	if c.TLS {
		log.Debug("TLS enabled")

		if c.TLS_CertFile == "" {
			c.TLS_CertFile = defaultTLSCertFile
		}
		c.TLS_CertFile = filepath.Join(configDir, c.TLS_CertFile)
		log.Debugf(" - Cert: %s", c.TLS_CertFile)

		if c.TLS_KeyFile == "" {
			c.TLS_KeyFile = defaultTLSKeyFile
		}
		c.TLS_KeyFile = filepath.Join(configDir, c.TLS_KeyFile)
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

func (c *Config) setDefaultSQLite(configDir string) {
	if c.DbDriver == sqliteDriver {
		if c.DbDSN == "" {
			c.DbDSN = defaultSQLiteName
		}
		c.DbDSN = filepath.Join(configDir, c.DbDSN)
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

func (c *Config) setDefaultTimeouts() {
	if c.IdentityServiceTimeoutMs == 0 {
		c.IdentityServiceTimeoutMs = defaultIdentityServiceTimeoutMs
	}

	if c.AuthServiceTimeoutMs == 0 {
		c.AuthServiceTimeoutMs = defaultAuthServiceTimeoutMs
	}

	if c.VerifyServiceTimeoutMs == 0 {
		c.VerifyServiceTimeoutMs = defaultVerifyServiceTimeoutMs
	}

	if c.VerificationTimeoutMs == 0 {
		c.VerificationTimeoutMs = defaultVerificationTimeoutMs
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

	if c.ServerIdentity == nil {
		defaultServerIdentityJSON, err := json.Marshal(defaultServerIdentities[c.Env])
		if err != nil {
			return err
		}

		c.ServerIdentity = &identity{}
		if err := json.Unmarshal(defaultServerIdentityJSON, c.ServerIdentity); err != nil {
			return err
		}
	}

	log.Infof("set backend verification key for %s environment: %s: %s",
		c.Env, c.ServerIdentity.UUID, base64.StdEncoding.EncodeToString(c.ServerIdentity.PubKey))

	return nil
}

// loadIdentitiesFile loads device identities from the identities JSON file.
// Returns without error if file does not exist.
func (c *Config) loadIdentitiesFile(configDir string) error {
	identitiesFile := filepath.Join(configDir, identitiesFileName)

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
