package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type chainChecker struct {
	Chan            chan []byte
	signatures      map[string][]byte
	signaturesMutex sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
}

func NewChainChecker() *chainChecker {
	c := &chainChecker{
		Chan:       make(chan []byte),
		signatures: make(map[string][]byte, numberOfTestIDs),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())

	// start chain checker routine
	go c.checkChain()

	return c
}

func (c *chainChecker) finish() {
	close(c.Chan)
	<-c.ctx.Done()
}

func (c *chainChecker) checkChain() {
	defer c.cancel()

	for b := range c.Chan {
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
