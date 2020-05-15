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
	"github.com/go-chi/chi"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var ConfigDir string

const (
	ConfigFile  = "config.json"
	ContextFile = "protocol.json"
)

var (
	Version = "v2.0.0"
	Build   = "local"
)

// handle graceful shutdown
func shutdown(signals chan os.Signal, p *ExtendedProtocol, wg *sync.WaitGroup, cancel context.CancelFunc) {
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// wait for all go routines to end, cancels the go routines contexts
	// and waits for the wait group
	cancel()
	wg.Wait()

	err := p.Deinit()
	if err != nil {
		log.Printf("unable to close database connection: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func main() {
	if len(os.Args) > 1 {
		ConfigDir = os.Args[1]
	}

	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load()
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.SecretBytes),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[string][]byte{}

	err = p.Init(conf.DSN, conf.Keys)
	if err != nil {
		log.Fatal(err)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	signals := make(chan os.Signal, 1)
	go shutdown(signals, &p, &wg, cancel)

	httpServer := api.HTTPServer{
		Router:   chi.NewMux(),
		TLS:      conf.TLS,
		CertFile: conf.TLS_CertFile,
		KeyFile:  conf.TLS_KeyFile,
	}

	// listen to messages to sign via http
	httpSrvSign := api.ServerEndpoint{
		Path:           fmt.Sprintf("/{%s}", api.UUIDKey),
		MessageHandler: make(chan api.HTTPMessage, 100),
		RequiresAuth:   true,
		AuthTokens:     conf.Devices,
	}
	httpServer.AddEndpoint(httpSrvSign)

	wg.Add(1)
	go signer(httpSrvSign.MessageHandler, &p, conf, ctx, &wg)

	// listen to messages to verify via http
	httpSrvVerify := api.ServerEndpoint{
		Path:           "/verify",
		MessageHandler: make(chan api.HTTPMessage, 100),
		RequiresAuth:   false,
		AuthTokens:     nil,
	}
	httpServer.AddEndpoint(httpSrvVerify)

	wg.Add(1)
	go verifier(httpSrvVerify.MessageHandler, &p, conf, ctx, &wg)

	// start HTTP server
	wg.Add(1)
	go httpServer.Serve(ctx, &wg)

	// wait forever, exit is handled via shutdown
	select {}
}
