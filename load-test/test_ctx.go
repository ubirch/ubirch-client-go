package main

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

type TestCtx struct {
	wg           *sync.WaitGroup
	chainChecker *ChainChecker
	failCounter  *FailCounter
	identities   map[string]string
	registerAuth string
}

func NewTestCtx() *TestCtx {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	log.SetLevel(log.DebugLevel)

	c := &Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	return &TestCtx{
		wg:           &sync.WaitGroup{},
		chainChecker: NewChainChecker(),
		failCounter:  NewFailCounter(),
		identities:   getTestIdentities(c),
		registerAuth: c.RegisterAuth,
	}
}

func (t *TestCtx) finish() {
	t.chainChecker.finish()
	t.failCounter.finish()
}
