package main

import (
	"flag"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	numberOfTestIDs        = 10
	requestsPerSecondPerID = 1
	numberOfRequestsPerID  = 100

	httpConnectionPoolSize = 50
	httpClientTimeoutSec   = 2
)

var (
	defaultConfigFile = "config.json"
	configFile        = flag.String("config", "", "file name of the configuration file. if omitted, configuration is read from \"config.json\".")
)

func main() {
	c := Config{}
	err := c.load()
	if err != nil {
		log.Fatalf("could not load configuration: %v", err)
	}

	sender := NewSender()

	identities, err := c.initTestIdentities(sender)
	if err != nil {
		log.Fatalf("could not initialize identities: %v", err)
	}

	totalNumberOfRequests := len(identities) * numberOfRequestsPerID
	log.Infof("%d identities, %d requests each => sending [ %d ] requests", len(identities), numberOfRequestsPerID, totalNumberOfRequests)
	log.Infof("%3d requests per second per identity", requestsPerSecondPerID)
	log.Infof("%3d requests per second overall", len(identities)*requestsPerSecondPerID)
	log.Infof("http connection pool size: %3d", httpConnectionPoolSize)
	log.Infof("  http client timeout [s]: %3d", httpClientTimeoutSec)

	wg := &sync.WaitGroup{}
	start := time.Now()

	i := 0
	n := len(identities)
	for uid, auth := range identities {
		offset := time.Duration((i*1000)/n) * time.Millisecond
		i += 1

		wg.Add(1)
		go sender.sendRequests(*c.url, uid, auth, offset, wg)
	}

	wg.Wait()
	duration := time.Since(start)

	sender.chainChecker.finish()

	log.Infof("[ %6d ] requests done after [ %7.3f ] seconds ", totalNumberOfRequests, duration.Seconds())

	for status, count := range sender.statusCounter {
		log.Infof("[ %6d ] x %s", count, status)
	}

	successCount := sender.statusCounter["200 OK"]
	successRate := (float32(successCount) / float32(totalNumberOfRequests)) * 100.

	log.Infof("               error rate: %3.2f", 100.-successRate)
	log.Infof("        avg response time: %s", sender.getAvgRequestDuration().String())
	log.Infof("     avg total throughput: %7.3f requests/second", float64(totalNumberOfRequests)/duration.Seconds())
	log.Infof("avg successful throughput: %7.3f requests/second", float64(successCount)/duration.Seconds())
}
