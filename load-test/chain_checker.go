package main

import (
	"bytes"
	"context"
	"encoding/base64"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

type ChainChecker struct {
	UPPs       chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	signatures map[string][]byte
}

func NewChainChecker() *ChainChecker {
	ctx, cancel := context.WithCancel(context.Background())

	c := &ChainChecker{
		UPPs:       make(chan []byte),
		ctx:        ctx,
		cancel:     cancel,
		signatures: make(map[string][]byte, numberOfTestIDs),
	}

	// start chain checker routine
	go c.checkChain()

	return c
}

func (c *ChainChecker) finish() {
	close(c.UPPs)
	<-c.ctx.Done()
}

func (c *ChainChecker) checkChain() {
	defer c.cancel()

	for uppBytes := range c.UPPs {
		upp, err := ubirch.Decode(uppBytes)
		if err != nil {
			log.Errorf("RESPONSE CONTAINED INVALID UPP: %v", err)
		}

		id := upp.GetUuid().String()
		signatureUPP := upp.GetSignature()
		prevSignatureLocal, found := c.signatures[id]

		if !found {
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

func (c *ChainChecker) SetSignature(id string, signature []byte) {
	if len(signature) != 64 {
		log.Fatal("invalid signature length")
	}

	c.signatures[id] = signature
}
