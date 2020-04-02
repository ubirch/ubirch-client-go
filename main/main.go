/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"github.com/go-chi/chi"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

var (
	Version = "v1.0.0"
	Build   = "local"
)

// handle graceful shutdown
func shutdown(signals chan os.Signal, p *ExtendedProtocol, wg *sync.WaitGroup, cancel context.CancelFunc, db Database) {
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// wait for all go routines to end, cancels the go routines contexts
	// and waits for the wait group
	cancel()
	wg.Wait()

	err := p.saveDB(db)
	if err != nil {
		log.Printf("unable to save p context: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	log.Printf("ubirch Golang client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load()
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	// create a ubirch Protocol
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.Secret),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[uuid.UUID]SignedKeyRegistration{}

	var authMap map[string]string // authMap contains a map from client uuid to password
	var keysMap map[string]string // authMap contains a map from client uuid to private key

	authMap, err = LoadAuth()
	if err != nil { // todo is this really critical?
		log.Fatalf("ERROR: unable to read authorizations from env: %v", err)
	}

	keysMap, err = LoadKeys()
	if err != nil { // todo is this really critical?
		log.Fatalf("ERROR: unable to read keys from env: %v", err)
	}

	db, err := NewPostgres(conf.DSN)
	if err != nil {
		log.Fatalf("Could not connect to database: %s", err)
	}

	err = db.GetProtocolContext(&p)
	if err != nil {
		log.Printf("empty keystore: %v", err)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	wg := sync.WaitGroup{}
	_, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	signals := make(chan os.Signal, 1)
	go shutdown(signals, &p, &wg, cancel, db)

	// initialize signer
	s := Signer{conf: conf, protocol: &p, DB: db, keyMap: keysMap}

	// listen to messages to sign via http
	router := chi.NewMux()
	handlers := HTTPSignHandlers{
		Signer:  s,
		AuthMap: authMap,
	}
	router.Post("/sign/{uuid}", handlers.SignerHandler)
	err = http.ListenAndServe(":8000", router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("error starting http service: %v", err)
	}
}
