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
	"os"
	"os/signal"
	"syscall"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
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
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	ctxManager, err := conf.GetCtxManager()
	if err != nil {
		log.Fatal(err)
	}

	// initialize ubirch protocol
	cryptoCtx := &ubirch.ECDSACryptoContext{}

	protocol, err := NewExtendedProtocol(cryptoCtx, ctxManager)
	if err != nil {
		log.Fatal(err)
	}

	client := &Client{
		authServiceURL:     conf.Niomon,
		verifyServiceURL:   conf.VerifyService,
		keyServiceURL:      conf.KeyService,
		identityServiceURL: conf.IdentityService,
	}

	idHandler := &IdentityHandler{
		protocol:            protocol,
		client:              client,
		subjectCountry:      conf.CSR_Country,
		subjectOrganization: conf.CSR_Organization,
	}

	// generate and register keys for known devices
	err = idHandler.initIdentities(conf.Devices)
	if err != nil {
		log.Fatal(err)
	}

	signer := Signer{
		protocol: protocol,
		client:   client,
	}

	verifier := Verifier{
		protocol:                      protocol,
		client:                        client,
		verifyFromKnownIdentitiesOnly: false, // TODO: make configurable
	}

	httpServer := HTTPServer{
		router:   NewRouter(),
		addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		certFile: conf.TLS_CertFile,
		keyFile:  conf.TLS_KeyFile,
	}
	if conf.CORS && isDevelopment { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	// set up endpoint for chaining
	httpServer.AddServiceEndpoint(ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", UUIDKey),
		Service: &ChainingService{
			Signer: &signer,
		},
	})

	// set up endpoint for signing
	httpServer.AddServiceEndpoint(ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", UUIDKey, OperationKey),
		Service: &SigningService{
			Signer: &signer,
		},
	})

	// set up endpoint for verification
	httpServer.AddServiceEndpoint(ServerEndpoint{
		Path: fmt.Sprintf("/%s", VerifyPath),
		Service: &VerificationService{
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

	// wrap up
	if err = protocol.Close(); err != nil {
		log.Error(err)
	}

	log.Info("shut down client")
}
