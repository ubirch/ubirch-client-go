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
	"flag"
	"fmt"
	"time"

	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/database"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/auditlogger"
	"github.com/ubirch/ubirch-client-go/main/config"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

var (
	// Version will be replaced with the tagged version during build time
	Version = "local build"
	// Revision will be replaced with the commit hash during build time
	Revision = "unknown"
)

func main() {
	const (
		serviceName = "ubirch-client"
		configFile  = "config.json"
	)

	var (
		serverID        = fmt.Sprintf("%s/%s", serviceName, Version)
		readinessChecks []func() error

		// declare command-line flags
		configDir = flag.String("config-directory", "", "path to the configuration file")
	)

	// parse command-line flags
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyMsg: "message",
		},
	})
	log.Printf("UBIRCH client (version=%s, revision=%s)", Version, Revision)
	auditlogger.SetServiceName(serviceName)

	// read configuration
	conf := &config.Config{}
	err := conf.Load(*configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	// initialize ubirch protocol
	ctxManager, err := database.NewDatabaseManager(conf.DbDriver, conf.DbDSN, &database.ConnectionParams{
		MaxOpenConns:    conf.DbMaxOpenConns,
		MaxIdleConns:    conf.DbMaxIdleConns,
		ConnMaxLifetime: time.Duration(conf.DbConnMaxLifetimeSec) * time.Second,
		ConnMaxIdleTime: time.Duration(conf.DbConnMaxIdleTimeSec) * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := ctxManager.Close()
		if err != nil {
			log.Error(err)
		}
	}()
	readinessChecks = append(readinessChecks, ctxManager.IsReady)

	protocol, err := repository.NewExtendedProtocol(ctxManager, conf)
	if err != nil {
		log.Fatal(err)
	}

	client := &clients.UbirchServiceClient{}
	client.KeyServiceURL = conf.KeyService
	client.IdentityServiceURL = conf.IdentityService
	client.IdentityServiceTimeout = time.Duration(conf.IdentityServiceTimeoutMs) * time.Millisecond
	client.AuthServiceURL = conf.Niomon
	client.AuthServiceTimeout = time.Duration(conf.AuthServiceTimeoutMs) * time.Millisecond
	client.VerifyServiceURL = conf.VerifyService
	client.VerifyServiceTimeout = time.Duration(conf.VerifyServiceTimeoutMs) * time.Millisecond

	idHandler := &handlers.IdentityHandler{
		Protocol:              protocol,
		SubmitKeyRegistration: client.SubmitKeyRegistration,
		RequestKeyDeletion:    client.RequestKeyDeletion,
		SubmitCSR:             client.SubmitCSR,
		SubjectCountry:        conf.CSR_Country,
		SubjectOrganization:   conf.CSR_Organization,
	}

	err = idHandler.InitIdentities(conf.Devices)
	if err != nil {
		log.Fatalf("initialization of identities from configuration failed: %v", err)
	}

	signer := handlers.Signer{
		SignerProtocol:                 protocol,
		VerifyBackendResponseSignature: protocol.VerifyBackendResponseSignature(conf.ServerIdentity.UUID, conf.ServerIdentity.PubKey),
		SendToAuthService:              client.SendToAuthService,
	}

	verifier := handlers.Verifier{
		VerifierProtocol:              protocol,
		RequestHash:                   client.RequestHash,
		RequestPublicKeys:             client.RequestPublicKeys,
		VerifyFromKnownIdentitiesOnly: conf.VerifyFromKnownIdentitiesOnly,
		VerificationTimeout:           time.Duration(conf.VerificationTimeoutMs) * time.Millisecond,
	}

	// set up HTTP server
	httpServer := h.InitHTTPServer(conf,
		idHandler.InitIdentity, idHandler.CreateCSR,
		protocol.CheckAuth, signer.Sign,
		verifier.Verify, verifier.VerifyOffline,
		idHandler.DeactivateKey, idHandler.ReactivateKey,
		serverID, readinessChecks)

	// start HTTP server (blocks until SIGINT or SIGTERM is received)
	if err = httpServer.Serve(); err != nil {
		log.Error(err)
	}
}
