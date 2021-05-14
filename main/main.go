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
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/clients"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"github.com/ubirch/ubirch-client-go/main/config"
	p "github.com/ubirch/ubirch-client-go/main/prometheus"
	"github.com/ubirch/ubirch-client-go/main/uc"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"golang.org/x/sync/errgroup"
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// handle graceful shutdown
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

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
	const configFile = "config.json"

	var (
		configDir      string
		migrate        bool
		initIdentities bool
	)

	if len(os.Args) > 1 {
		for i, arg := range os.Args[1:] {
			log.Infof("arg #%d: %s", i+1, arg)
			if arg == vars.MigrateArg {
				migrate = true
			} else if arg == vars.InitArg {
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

	ctxManager, err := repository.GetCtxManager(conf)
	if err != nil {
		log.Fatal(err)
	}

	client := &clients.Client{
		AuthServiceURL:     conf.Niomon,
		VerifyServiceURL:   conf.VerifyService,
		KeyServiceURL:      conf.KeyService,
		IdentityServiceURL: conf.IdentityService,
	}

	// initialize ubirch protocol
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
		Protocol:             protocol,
		AuthTokensBuffer:     map[uuid.UUID]string{},
		AuthTokenBufferMutex: &sync.RWMutex{},
	}

	verifier := handlers.Verifier{
		Protocol:                      protocol,
		VerifyFromKnownIdentitiesOnly: false, // TODO: make configurable
	}

	httpServer := handlers.HTTPServer{
		Router:   handlers.NewRouter(),
		Addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}
	if conf.CORS && config.IsDevelopment { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	globals := handlers.Globals{
		Config:  conf,
		Version: Version,
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	// set up metrics
	p.InitPromMetrics(httpServer.Router)

	// set up endpoint for liveliness checks
	httpServer.Router.Get("/healtz", h.Health(globals.Version))

	// start HTTP server
	serverReadyCtx, serverReady := context.WithCancel(context.Background())
	g.Go(func() error {
		return httpServer.Serve(ctx, serverReady)
	})
	// wait for server to start
	<-serverReadyCtx.Done()

	// set up endpoint for identity registration
	identity := createIdentityUseCases(globals, idHandler)
	httpServer.Router.Put("/register", identity.handler.Put(identity.storeIdentity, identity.checkIdentity))

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", vars.UUIDKey),
		Service: &handlers.ChainingService{
			Signer: &signer,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", vars.UUIDKey, vars.OperationKey),
		Service: &handlers.SigningService{
			Signer: &signer,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/%s", vars.VerifyPath),
		Service: &handlers.VerificationService{
			Verifier: &verifier,
		},
	})

	// set up endpoint for readiness checks
	httpServer.Router.Get("/readiness", h.Health(globals.Version))
	log.Info("ready")

	// wait for all go routines of the waitgroup to return
	if err = g.Wait(); err != nil {
		log.Error(err)
	}

	log.Debug("shut down client")
}

type identities struct {
	handler       handlers.Identity
	storeIdentity handlers.StoreIdentity
	fetchIdentity handlers.FetchIdentity
	checkIdentity handlers.CheckIdentityExists
}

func createIdentityUseCases(globals handlers.Globals, handler *handlers.IdentityHandler) identities {
	return identities{
		handler:       handlers.NewIdentity(globals),
		storeIdentity: uc.NewIdentityStorer(handler),
		fetchIdentity: uc.NewIdentityFetcher(handler),
		checkIdentity: uc.NewIdentityChecker(handler),
	}
}
