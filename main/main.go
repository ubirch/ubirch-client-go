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
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/config"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

// handle graceful shutdown
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Infof("shutting down after receiving: %v", sig)

	// cancel the go routines contexts
	cancel()
}

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
		configDir      string
		migrate        bool
		initIdentities bool
		serverID       = fmt.Sprintf("%s/%s", serviceName, Version)
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
	conf := config.Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	if migrate {
		err := repository.Migrate(conf)
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

	client := &clients.Client{
		AuthServiceURL:     conf.Niomon,
		VerifyServiceURL:   conf.VerifyService,
		KeyServiceURL:      conf.KeyService,
		IdentityServiceURL: conf.IdentityService,
	}

	protocol, err := repository.NewExtendedProtocol(ctxManager, conf.SecretBytes32, client)
	if err != nil {
		log.Fatal(err)
	}

	idHandler := &handlers.IdentityHandler{
		Protocol:            protocol,
		SubjectCountry:      conf.CSR_Country,
		SubjectOrganization: conf.CSR_Organization,
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
		Protocol: protocol,
	}

	verifier := handlers.Verifier{
		Protocol:                      protocol,
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
	httpServer.Router.Method(http.MethodGet, "/metrics", prom.Handler())

	// set up endpoint for identity registration
	httpServer.Router.Put(h.RegisterEndpoint, handlers.Register(conf.RegisterAuth, idHandler.InitIdentity))

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", h.UUIDKey),
		Service: &handlers.ChainingService{
			CheckAuth: protocol.CheckAuth,
			Chain:     signer.Chain,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", h.UUIDKey, h.OperationKey),
		Service: &handlers.SigningService{
			CheckAuth: protocol.CheckAuth,
			Sign:      signer.Sign,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(h.ServerEndpoint{
		Path: h.VerifyPath,
		Service: &handlers.VerificationService{
			Verify: verifier.Verify,
		},
	})

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get("/healthz", h.Health(serverID))
	httpServer.Router.Get("/readyz", h.Health(serverID)) // todo: implement real readiness check

	// set up graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	go shutdown(cancel)

	// start HTTP server (blocks)
	if err = httpServer.Serve(ctx); err != nil {
		log.Error(err)
	}

	log.Debug("shut down")
}
