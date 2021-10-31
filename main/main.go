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
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/config"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
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
		MigrateArg  = "--migrate"
		InitArg     = "--init-identities-conf"
	)

	var (
		configDir       string
		migrate         bool
		initIdentities  bool
		serverID        = fmt.Sprintf("%s/%s", serviceName, Version)
		readinessChecks []func() error
	)

	if len(os.Args) > 1 {
		for i, arg := range os.Args[1:] {
			log.Infof("arg #%d: %s", i+1, arg)
			if arg == MigrateArg {
				migrate = true
			} else if arg == InitArg {
				initIdentities = true
			} else {
				configDir = arg
			}
		}
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH client (version=%s, revision=%s)", Version, Revision)

	// read configuration
	conf := &config.Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	if migrate {
		err := repository.Migrate(conf, configDir)
		if err != nil {
			log.Fatalf("migration failed: %v", err)
		}
		os.Exit(0)
	}

	// initialize ubirch protocol
	ctxManager, err := repository.GetContextManager(conf)
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
	client.AuthServiceURL = conf.Niomon
	client.VerifyServiceURL = conf.VerifyService

	idHandler := &handlers.IdentityHandler{
		Protocol:              protocol,
		SubmitKeyRegistration: client.SubmitKeyRegistration,
		SubmitCSR:             client.SubmitCSR,
		SubjectCountry:        conf.CSR_Country,
		SubjectOrganization:   conf.CSR_Organization,
	}

	if initIdentities {
		err = idHandler.InitIdentities(conf.Devices)
		if err != nil {
			log.Fatalf("initialization of identities from configuration failed: %v", err)
		}
		log.Infof("successfully initialized identities from configuration")
		os.Exit(0)
	}

	signer := handlers.Signer{
		Protocol:          protocol,
		SendToAuthService: client.SendToAuthService,
	}

	verifier := handlers.Verifier{
		Protocol:                      protocol,
		RequestHash:                   client.RequestHash,
		RequestPublicKeys:             client.RequestPublicKeys,
		VerifyFromKnownIdentitiesOnly: false, // TODO: make configurable
	}

	// set up HTTP server
	httpServer := h.HTTPServer{
		Router:   h.NewRouter(),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	if conf.CORS && config.IsDevelopment { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	// set up metrics
	httpServer.Router.Method(http.MethodGet, h.MetricsEndpoint, prom.Handler())

	// set up endpoint for identity registration
	httpServer.Router.Put(h.RegisterEndpoint, h.Register(conf.RegisterAuth, idHandler.InitIdentity))

	// set up endpoint for CSRs
	fetchCSREndpoint := path.Join(h.UUIDPath, h.CSREndpoint) // /<uuid>/csr
	httpServer.Router.Get(fetchCSREndpoint, h.FetchCSR(conf.RegisterAuth, idHandler.CreateCSR))

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: h.UUIDPath,
		Service: &h.ChainingService{
			CheckAuth: protocol.CheckAuth,
			Chain:     signer.Chain,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: path.Join(h.UUIDPath, h.OperationKey),
		Service: &h.SigningService{
			CheckAuth: protocol.CheckAuth,
			Sign:      signer.Sign,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: h.VerifyPath,
		Service: &h.VerificationService{
			Verify: verifier.Verify,
		},
	})

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get(h.LivenessCheckEndpoint, h.Health(serverID))
	httpServer.Router.Get(h.ReadinessCheckEndpoint, h.Ready(serverID, readinessChecks))

	// start HTTP server (blocks until SIGINT or SIGTERM is received)
	if err = httpServer.Serve(); err != nil {
		log.Error(err)
	}
}
