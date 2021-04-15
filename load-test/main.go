package main

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL          = "http://localhost:8080/"
	configFile             = "config.json"
	numberOfTestIDs        = 100
	numberOfRequestsPerID  = 10
	requestsPerSecondPerID = 1
)

func main() {
	testCtx := NewTestCtx()
	sender := &Sender{testCtx: testCtx}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(testCtx.identities), numberOfRequestsPerID, len(testCtx.identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", requestsPerSecondPerID*numberOfTestIDs)

	start := time.Now()

	for uid, auth := range testCtx.identities {
		testCtx.wg.Add(1)
		go sender.sendRequests(uid, auth)
	}

	testCtx.wg.Wait()
	log.Infof(" = = = => requests done after [ %7.3f ] seconds <= = = = ", time.Since(start).Seconds())
	testCtx.teardown()
}
