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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/handlers"
	"github.com/ubirch/ubirch-client-go/main/uc"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"golang.org/x/sync/errgroup"

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

func main() {
	const (
		Version    = "v2.0.0"
		Build      = "local"
		configFile = "config.json"
	)

	var configDir string
	migrate := false
	initIdentities := false

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
	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := config.Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	if migrate {
		err := handlers.Migrate(conf)
		if err != nil {
			log.Fatalf("migration failed: %v", err)
		}
		log.Infof("successfully migrated file based context into database")
		os.Exit(0)
	}

	ctxManager, err := handlers.GetCtxManager(conf)
	if err != nil {
		log.Fatal(err)
	}

	client := &handlers.Client{
		AuthServiceURL:     conf.Niomon,
		VerifyServiceURL:   conf.VerifyService,
		KeyServiceURL:      conf.KeyService,
		IdentityServiceURL: conf.IdentityService,
	}

	// initialize ubirch protocol
	protocol, err := handlers.NewExtendedProtocol(ctxManager, conf.SecretBytes32, client)
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

	identity := createIdentityUseCases(globals, idHandler)
	httpServer.Router.Put("/register", identity.handler.Put(identity.storeIdentity, identity.checkIdentity))

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", handlers.UUIDKey),
		Service: &handlers.ChainingService{
			Signer: &signer,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", handlers.UUIDKey, handlers.OperationKey),
		Service: &handlers.SigningService{
			Signer: &signer,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(handlers.ServerEndpoint{
		Path: fmt.Sprintf("/%s", handlers.VerifyPath),
		Service: &handlers.VerificationService{
			Verifier: &verifier,
		},
	})

	// start HTTP server
	g.Go(func() error {
		return httpServer.Serve(ctx)
	})

	// wait for all go routines of the waitgroup to return
	if err = g.Wait(); err != nil {
		log.Error(err)
	}

	log.Info("shut down client")
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
