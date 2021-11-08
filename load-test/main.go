package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL          = "http://localhost:8080"
	configFile             = "config.json"
	numberOfTestIDs        = 100
	numberOfRequestsPerID  = 100
	requestsPerSecondPerID = 1
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	c := Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	identities := c.GetTestIdentities()
	sender := NewSender()

	for id, auth := range identities {
		err := sender.register(id, auth, c.RegisterAuth)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(identities), numberOfRequestsPerID, len(identities)*numberOfRequestsPerID)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(identities)*requestsPerSecondPerID)

	wg := &sync.WaitGroup{}
	start := time.Now()

	i := 0
	n := len(identities)
	for uid, auth := range identities {
		offset := time.Duration((i*1000)/n) * time.Millisecond
		i += 1

		wg.Add(1)
		go sender.sendRequests(uid, auth, offset, wg)
	}

	wg.Wait()
	duration := time.Since(start)

	sender.chainChecker.finish()

	log.Infof("[ %6d ] requests done after [ %7.3f ] seconds ", len(identities)*numberOfRequestsPerID, duration.Seconds())

	for status, count := range sender.statusCounter {
		log.Infof("[ %6d ] x %s", count, status)
	}

	log.Infof("avg response time: %s", sender.getAvgRequestDuration().String())
	avgReqsPerSec := float64(len(identities)*numberOfRequestsPerID) / duration.Seconds()
	log.Infof("avg total throughput: %7.3f requests/second", avgReqsPerSec)
	avgReqsPerSecSuccess := float64(sender.statusCounter["200 OK"]) / duration.Seconds()
	log.Infof("avg successful throughput: %7.3f requests/second", avgReqsPerSecSuccess)
}
