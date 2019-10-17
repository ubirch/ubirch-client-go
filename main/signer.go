package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch"
	"log"
)

// handle incoming udp messages, create and send a ubirch protocol message (UPP)
func sign(handler chan UDPMessage, p *ExtendedProtocol, conf Config, done chan bool) {
	//client, err := mqtt(conf.Mqtt.Address, conf.Mqtt.User, conf.Mqtt.Password, nil)
	//if err != nil {
	//	log.Printf("unable to connect to MQTT server: %v", err)
	//}

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
					cert, err := getSignedCertificate(p, name, uid)
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

				resp, err := post(upp, conf.Niomon, map[string]string{
					"x-ubirch-hardware-id": name,
					"x-ubirch-auth-type":   conf.Auth,
					"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
				})
				if err != nil {
					log.Printf("%s: send failed: %q\n", name, resp)
					continue
				}
				log.Printf("%s: %q\n", name, resp)

				// save state for every message
				err = p.save(ContextFile)
				if err != nil {
					log.Printf("unable to save protocol context: %v", err)
				}
			}
		case <-done:
			log.Println("finishing handler")
			return
		}
	}
}
