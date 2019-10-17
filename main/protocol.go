package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type ExtendedProtocol struct {
	ubirch.Protocol
	Certificates map[uuid.UUID]SignedKeyRegistration
}

// saves current ubirch-protocol context, storing keys and signatures
func (p *ExtendedProtocol) save(file string) error {
	err := os.Rename(file, file+".bck")
	if err != nil {
		log.Printf("unable to create protocol context backup: %v", err)
	}

	contextBytes, _ := json.MarshalIndent(p, "", "  ")
	err = ioutil.WriteFile(file, contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

func (p *ExtendedProtocol) read(contextBytes []byte) error {
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
func (p *ExtendedProtocol) load(file string) error {
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = p.read(contextBytes)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			err = p.load(file + ".bck")
			if err != nil {
				return err
			}
		}
	}
	return nil
}
