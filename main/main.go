package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/thinkberg/ubirch-protocol-go/ubirch"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[uuid.UUID]SignedKeyRegistration
}

// saves current ubirch-protocol context, storing keys and signatures
func saveProtocolContext(p *ExtendedProtocol) error {
	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	err := ioutil.WriteFile("protocol.json", contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

// loads current ubirch-protocol context, loading keys and signatures
func loadProtocolContext(p *ExtendedProtocol) error {
	contextBytes, err := ioutil.ReadFile("protocol.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		log.Println(p.Signatures)
		return nil
	}
}

func main() {
	// load configuration
	conf := Config{}
	err := conf.Load("config.json")
	if err != nil {
		log.Fatalf("unable to load configuration: %v", err)
	}

	// create a Crypto context
	context := &ubirch.CryptoContext{&keystore.Keystore{}, map[string]uuid.UUID{}}

	// create a ubirch Protocol
	p := ExtendedProtocol{}
	p.Crypto = context
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[uuid.UUID]SignedKeyRegistration{}

	// try to load an existing p context (keystore)
	err = loadProtocolContext(&p)
	if err != nil {
		log.Printf("empty keystore: %v", err)
	}

	// set up graceful shutdown handling
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true

		log.Println("saving p context")
		err := saveProtocolContext(&p)
		if err != nil {
			log.Printf("unable to save p context: %v", err)
			os.Exit(1)
		}

		os.Exit(0)
	}()

	// create a message handler that parses the UDP message and creates UPPs
	handler := make(chan UDPMessage, 100)
	go func() {
		registeredUUIDs := make(map[uuid.UUID]bool)
		for {
			select {
			case msg := <-handler:
				log.Printf("received %v: %s\n", msg.addr, hex.EncodeToString(msg.data))
				if len(msg.data) > 16 {
					uid, err := uuid.FromBytes(msg.data[:16])
					if err != nil {
						log.Printf("warning: UUID not parsable: (%s) %v\n", hex.EncodeToString(msg.data[:16]), err)
						continue
					}
					name := uid.String()

					// check if certificate exists and generate key pair + registration
					_, err = p.Crypto.GetKey(name)
					if err != nil {
						err = p.Crypto.GenerateKey(name, uid)
						if err != nil {
							log.Printf("%s: unable to generate key pair: %v\n", name, err)
							continue
						}
					}
					_, registered := registeredUUIDs[uid]
					if !registered {
						cert, err := getSignedCertificate(&p, name, uid)
						if err != nil {
							log.Printf("%sunable to generate signed certificate: %v\n", name, err)
							continue
						}
						resp, err := post(cert, fmt.Sprintf("%spubkey", conf.KeyService),
							map[string]string{"Content-Type": "application/json"})
						if err != nil {
							log.Printf("%s: unable to register public key: %v\n", name, err)
							continue
						}
						log.Printf("%s: registered key: %v", name, string(resp))
						registeredUUIDs[uid] = true
					}

					// send UPP
					hash := sha256.Sum256(msg.data[16:])
					log.Printf("%s: hash %s (%s)\n", name, base64.StdEncoding.EncodeToString(hash[:]),
						hex.EncodeToString(hash[:]))
					upp, err := p.Sign(name, hash[:], ubirch.Chained)
					if err != nil {
						log.Printf("%s: unable to create UPP: %v", name, err)
					}
					log.Printf("%s: UPP %s\n", name, hex.EncodeToString(upp))
				}
			case <-done:
				log.Println("finishing handler")
				return
			}
		}
	}()

	// connect a udp server to listen to messages
	udpServer := UDPServer{handler}
	err = udpServer.Listen("", 15001)
	if err != nil {
		log.Fatalf("error starting UDP server: %v", err)
	}
}
