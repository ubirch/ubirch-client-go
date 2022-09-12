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
	"github.com/ubirch/ubirch-client-go/main/auditlogger"
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
	)

	var (
		configDir       string
		migrate         bool
		serverID        = fmt.Sprintf("%s/%s", serviceName, Version)
		readinessChecks []func() error
	)

	log.SetFormatter(&log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyMsg: "message",
		},
	})
	log.Printf("UBIRCH client (version=%s, revision=%s)", Version, Revision)
	auditlogger.SetServiceName(serviceName)

	if len(os.Args) > 1 {
		for i, arg := range os.Args[1:] {
			log.Infof("arg #%d: %s", i+1, arg)
			if arg == MigrateArg {
				migrate = true
			} else {
				configDir = arg
			}
		}
	}

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

	// set up endpoint for key status updates (de-/re-activation)
	httpServer.Router.Put(h.ActiveUpdateEndpoint, h.UpdateActive(conf.RegisterAuth, idHandler.DeactivateKey, idHandler.ReactivateKey))

	// set up endpoint for CSR creation
	fetchCSREndpoint := path.Join(h.UUIDPath, h.CSREndpoint) // /<uuid>/csr
	httpServer.Router.Get(fetchCSREndpoint, h.FetchCSR(conf.RegisterAuth, idHandler.CreateCSR))

	// set up endpoints for signing
	signingService := &h.SigningService{
		CheckAuth: protocol.CheckAuth,
		Sign:      signer.Sign,
	}

	// chain:              <uuid>
	// chain hash:         <uuid>/hash
	// chain offline:      <uuid>/offline
	// chain offline hash: <uuid>/offline/hash
	httpServer.AddServiceEndpoint(h.UUIDPath,
		signingService.HandleRequest(h.ChainHash),
		true,
	)

	// sign:              <uuid>/anchor
	// sign hash:         <uuid>/anchor/hash
	// sign offline:      <uuid>/anchor/offline
	// sign offline hash: <uuid>/anchor/offline/hash
	httpServer.AddServiceEndpoint(path.Join(h.UUIDPath, string(h.AnchorHash)),
		signingService.HandleRequest(h.AnchorHash),
		true,
	)

	// disable:      /<uuid>/disable
	// disable hash: /<uuid>/disable/hash
	httpServer.AddServiceEndpoint(path.Join(h.UUIDPath, string(h.DisableHash)),
		signingService.HandleRequest(h.DisableHash),
		false,
	)

	// enable:      /<uuid>/enable
	// enable hash: /<uuid>/enable/hash
	httpServer.AddServiceEndpoint(path.Join(h.UUIDPath, string(h.EnableHash)),
		signingService.HandleRequest(h.EnableHash),
		false,
	)

	// delete:      /<uuid>/delete
	// delete hash: /<uuid>/delete/hash
	httpServer.AddServiceEndpoint(path.Join(h.UUIDPath, string(h.DeleteHash)),
		signingService.HandleRequest(h.DeleteHash),
		false,
	)

	// set up endpoints for verification
	verificationService := &h.VerificationService{
		Verify:        verifier.Verify,
		VerifyOffline: verifier.VerifyOffline,
	}

	// verify:              /verify
	// verify hash:         /verify/hash
	// verify offline:      /verify/offline
	// verify offline hash: /verify/offline/hash
	httpServer.AddServiceEndpoint(h.VerifyPath,
		verificationService.HandleRequest,
		true,
	)

	// set up endpoints for liveness and readiness checks
	httpServer.Router.Get(h.LivenessCheckEndpoint, h.Health(serverID))
	httpServer.Router.Get(h.ReadinessCheckEndpoint, h.Ready(serverID, readinessChecks))

	// start HTTP server (blocks until SIGINT or SIGTERM is received)
	if err = httpServer.Serve(); err != nil {
		log.Error(err)
	}
}
