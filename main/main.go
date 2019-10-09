package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/ubirch/ubirch-protocol-go/ubirch"
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
		log.Printf("%d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))
		return nil
	}
}

func main() {
	// load configuration
	conf := Config{}
	err := conf.Load("config.json")
	if err != nil {
		fmt.Println("ERROR: unable to load configuration: ", err)
		fmt.Println("ERROR: a configuration file is required to run the client")
		fmt.Println()
		fmt.Println("Follow these steps to configure this client:")
		fmt.Println("  1. visit https://console.demo.ubirch.com and register a user")
		fmt.Println("  2. register a new device and save the device configuration in config.json")
		fmt.Println("  3. restart the client")
		os.Exit(1)
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
							log.Printf("%s: unable to generate signed certificate: %v\n", name, err)
							continue
						}
						log.Printf("CERT [%s]\n", cert)

						resp, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
						if err != nil {
							log.Printf("%s: unable to register public key: %v\n", name, err)
							continue
						}
						log.Printf("%s: registered key: (%d) %v", name, len(resp), string(resp))
						registeredUUIDs[uid] = true
					}

					// send UPP (hash
					hash := sha256.Sum256(msg.data)
					log.Printf("%s: hash %s (%s)\n", name,
						base64.StdEncoding.EncodeToString(hash[:]),
						hex.EncodeToString(hash[:]))

					upp, err := p.Sign(name, hash[:], ubirch.Chained)
					if err != nil {
						log.Printf("%s: unable to create UPP: %v\n", name, err)
						continue
					}
					log.Printf("%s: UPP %s\n", name, hex.EncodeToString(upp))
					//ok, err := p.Verify(name, upp, ubirch.Chained)
					//if err != nil || !ok {
					//	log.Printf("self verification failed: %v\n", err)
					//} else {
					//	log.Println("self verification okay")
					//}

					resp, err := post(upp, conf.Niomon, map[string]string{
						"x-ubirch-hardware-id": name,
						"x-ubirch-auth-type":   "ubirch",
						"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
					})
					if err != nil {
						log.Printf("%s: send failed: %q\n", name, resp)
						continue
					}
					log.Printf("%s: %q\n", name, resp)

					// save state for every message
					err = saveProtocolContext(&p)
					if err != nil {
						log.Printf("unable to save protocol context: %v", err)
					}
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
