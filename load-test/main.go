package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL         = "http://localhost:8080/"
	configFile            = "config.json"
	numberOfTestIDs       = 100
	numberOfRequestsPerID = 4
)

func main() {
	setup()
	var wg sync.WaitGroup

	testIdentities := getTestIdentities()
	chainChecker := NewChainChecker()

	start := time.Now()

	for uid, auth := range testIdentities {
		sendRequests(uid, auth, chainChecker.Chan, &wg)
	}

	log.Infof(" = = = => requests sent after %7.3f seconds <= = = = ", time.Since(start).Seconds())
	wg.Wait()
	log.Infof(" = = = => requests done after %7.3f seconds <= = = = ", time.Since(start).Seconds())

	chainChecker.finish()
}
