package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/ubirch/ubirch-protocol-go/ubirch"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)
import MQTT "github.com/eclipse/paho.mqtt.golang"

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[uuid.UUID]SignedKeyRegistration
}

// saves current ubirch-protocol context, storing keys and signatures
func saveProtocolContext(p *ExtendedProtocol) error {
	err := os.Rename("protocol.json", "protocol.json.bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}

	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	err = ioutil.WriteFile("protocol.json", contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

func loadProtocolContextJson(p *ExtendedProtocol, contextBytes []byte) error {
	err := json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Printf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		log.Printf("%d certificates, %d signatures\n", len(p.Certificates), len(p.Signatures))
		return nil
	}
}

// loads current ubirch-protocol context, loading keys and signatures
func loadProtocolContext(p *ExtendedProtocol, file string) error {
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = loadProtocolContextJson(p, contextBytes)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			err = loadProtocolContext(p, file+".bck")
			if err != nil {
				return err
			}
		}
	}
	return nil
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
	err = loadProtocolContext(&p, "protocol.json")
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

	mqttHandler := func(client MQTT.Client, msg MQTT.Message) {
		data := msg.Payload()
		fmt.Printf("MSG: %s\n", hex.EncodeToString(data))

		verified, err := p.Verify("switch", data, ubirch.Chained)
		if err != nil {
			log.Printf("error verifying message: %v", err)
		}
		if !verified {
			log.Printf("message signature can't be verified")
		}

		raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:14001")
		if err != nil {
			return
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return
		}
		//noinspection ALL
		defer conn.Close()

		n, err := io.Copy(conn, bytes.NewReader(data))
		if err != nil {
			log.Printf("can't write to UDP socket: %v", err)
		} else {
			log.Printf("sent %d bytes to UDP: %s", n, hex.EncodeToString(data))
		}
		log.Printf("sent command %s to UDP socket", hex.EncodeToString(data))

		//token := client.Publish("nn/result", 0, false, text)
		//token.Wait()
	}

	// set up mqtt client
	err = mqtt(conf.Mqtt.Address, conf.Mqtt.User, conf.Mqtt.Password, mqttHandler)
	if err != nil {
		log.Printf("mqtt client failed to start: %v", err)
	}

	// connect a udp server to listen to messages
	udpServer := UDPServer{handler}
	err = udpServer.Listen("", 15001)
	if err != nil {
		log.Fatalf("error starting UDP server: %v", err)
	}
}
