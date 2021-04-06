package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"net/http"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type signingResponse struct {
	Error     string       `json:"error,omitempty"`
	Operation string       `json:"operation,omitempty"`
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type Config struct {
	Devices map[string]string `json:"devices"`
}

func (c *Config) Load(filename string) error {
	fileHandle, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
}

func getTestIdentities(num int) map[string]string {
	c := Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	testIdentities := make(map[string]string, num)

	for uid, auth := range c.Devices {
		testIdentities[uid] = auth
		if len(testIdentities) == num {
			break
		}
	}

	return testIdentities
}

func setup() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	log.SetLevel(log.DebugLevel)
}

type chainChecker struct {
	signatures      map[string][]byte
	signaturesMutex sync.RWMutex
}

func (c *chainChecker) checkChain(uppBytes <-chan []byte, cancel context.CancelFunc) {
	defer cancel()

	for b := range uppBytes {
		upp, err := ubirch.Decode(b)
		if err != nil {
			log.Errorf("RESPONSE CONTAINED INVALID UPP: %v", err)
		}

		id := upp.GetUuid().String()
		signatureUPP := upp.GetSignature()
		prevSignatureLocal := c.GetSignature(id)

		if prevSignatureLocal == nil {
			c.SetSignature(id, signatureUPP)
			continue
		}

		prevSignatureUPP := upp.GetPrevSignature()

		if !bytes.Equal(prevSignatureLocal, prevSignatureUPP) {
			log.Errorf("PREV SIGNATURE MISMATCH: local %s, got %s",
				base64.StdEncoding.EncodeToString(prevSignatureLocal),
				base64.StdEncoding.EncodeToString(prevSignatureUPP),
			)
		}

		c.SetSignature(id, signatureUPP)
	}
}

func (c *chainChecker) GetSignature(id string) []byte {
	c.signaturesMutex.RLock()
	defer c.signaturesMutex.RUnlock()

	return c.signatures[id]
}

func (c *chainChecker) SetSignature(id string, signature []byte) {
	if len(signature) != 64 {
		log.Fatal("invalid signature length")
	}

	c.signaturesMutex.Lock()
	defer c.signaturesMutex.Unlock()

	c.signatures[id] = signature
}
