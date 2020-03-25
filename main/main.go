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
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/ubirch/ubirch-go-http-server/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	AuthFile    = "auth.json"
	ConfigFile  = "config.json"
	ContextFile = "protocol.json"
)

var (
	Version = "v1.0.0"
	Build   = "local"
)

// handle graceful shutdown
func shutdown(signals chan os.Signal, p *ExtendedProtocol, path string, wg *sync.WaitGroup, cancel context.CancelFunc) {
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// wait for all go routines to end, cancels the go routines contexts
	// and waits for the wait group
	cancel()
	wg.Wait()

	err := p.save(path + ContextFile)
	if err != nil {
		log.Printf("unable to save p context: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func main() {
	pathToConfig := ""
	if len(os.Args) > 1 {
		pathToConfig = os.Args[1]
	}

	log.Printf("ubirch Golang client (%s, build=%s)", Version, Build)
	// read configuration
	conf := Config{}

	err := conf.Load(pathToConfig + ConfigFile)
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}


	// create a ubirch Protocol
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[uuid.UUID]SignedKeyRegistration{}
	
	// initialize protocol
	p.Init()

	var authMap map[string]string
	var keysMap map[string]string
	var db Database

	if conf.DSN != "" {
		// use the database

		db, err = NewPostgres(conf.DSN)
		if err != nil {
			log.Fatalf("Could not connect to database: %s", err)
		}

		authMap, keysMap, err = db.GetAuthKeysMaps()
		if err != nil {
			log.Fatalf("ERROR: unable to read authorizations from database: %v", err)
		}

		err = db.GetProtocolContext(&p)
		if err != nil {
			log.Printf("empty keystore: %v", err)
		}


	} else {
		// read configurations from file

		authMap, err = LoadAuth(pathToConfig + AuthFile)
		if err != nil { // todo is this really critical?
			log.Fatalf("ERROR: unable to read authorizations from file (%s): %v", AuthFile, err)
		}

		keysMap, err = LoadKeys(pathToConfig + AuthFile)
		if err != nil { // todo is this really critical?
			log.Fatalf("ERROR: unable to read keys from file (%s): %v", AuthFile, err)
		}

		// try to read an existing p context (keystore)
		err = p.load(pathToConfig + ContextFile)
		if err != nil {
			log.Printf("empty keystore: %v", err)
		}
	}


	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	signals := make(chan os.Signal, 1)
	go shutdown(signals, &p, pathToConfig, &wg, cancel)

	// create a messages channel that parses the UDP message and creates UPPs
	msgsToSign := make(chan []byte, 100)
	signResp := make(chan api.Response, 100)
	go signer(msgsToSign, signResp, &p, pathToConfig, conf, keysMap, ctx, &wg)
	wg.Add(1)

	// connect a udp server to listen to messages to ubirch (sign)
	udpSrvSign := UDPServer{receiveHandler: msgsToSign}
	err = udpSrvSign.Listen(conf.Interface.RxCert, ctx, &wg)
	if err != nil {
		log.Fatalf("error starting signing service: %v", err)
	}
	wg.Add(1)

	// listen to messages to sign via http
	httpSrvSign := api.HTTPServer{ReceiveHandler: msgsToSign, ResponseHandler: signResp, Endpoint: "/sign/", Auth: authMap}
	go httpSrvSign.Listen(ctx, &wg)
	wg.Add(1)

	// create a messages channel that hashes messages and fetches the UPP to verify
	msgsToVrfy := make(chan []byte, 100)
	responses := make(chan []byte, 100)
	go verifier(msgsToVrfy, responses, &p, pathToConfig, conf, ctx, &wg)
	wg.Add(1)

	// connect a udp server to listen to messages to verify
	udpSrvVrfy := UDPServer{receiveHandler: msgsToVrfy, responseHandler: responses}
	err = udpSrvVrfy.Listen(conf.Interface.RxVerify, ctx, &wg)
	if err != nil {
		log.Fatalf("error starting verification service: %v", err)
	}
	wg.Add(1)

	// set up udp server to send message responses
	err = udpSrvVrfy.Serve(conf.Interface.TxVerify, ctx, &wg)
	if err != nil {
		log.Fatalf(fmt.Sprintf("error setting up response sender: %v", err))
	}
	wg.Add(1)

	// wait forever, exit is handled via shutdown
	select {}
}
