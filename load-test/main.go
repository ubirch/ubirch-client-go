package main

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL          = "http://127.0.0.1:8081"
	configFile             = "config.json"
	numberOfTestIDs        = 1
	numberOfRequestsPerID  = 500
	requestsPerSecondPerID = 500
)

func main() {
	testCtx := NewTestCtx()
	sender := NewSender(testCtx)

	for id, auth := range testCtx.identities {
		err := sender.register(id, auth, testCtx.registerAuth)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(testCtx.identities), numberOfRequestsPerID, len(testCtx.identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(testCtx.identities)*requestsPerSecondPerID)

	start := time.Now()

	for uid, auth := range testCtx.identities {
		testCtx.wg.Add(1)
		go sender.sendRequests(uid, auth)
	}

	testCtx.wg.Wait()
	log.Infof(" = = = => [ %4d ] requests done after [ %7.3f ] seconds <= = = = ", len(testCtx.identities)*numberOfRequestsPerID, time.Since(start).Seconds())
	testCtx.finish()
}
