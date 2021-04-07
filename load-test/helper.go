package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"os"
)

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

func setup() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	log.SetLevel(log.DebugLevel)
}

func getTestIdentities() map[string]string {
	c := Config{}
	err := c.Load(configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	testIdentities := make(map[string]string, numberOfTestIDs)

	for uid, auth := range c.Devices {
		testIdentities[uid] = auth
		if len(testIdentities) == numberOfTestIDs {
			break
		}
	}

	log.Infof("%d identities, %d requests each", len(testIdentities), numberOfRequestsPerID)
	log.Infof(" = = = => sending %d requests <= = = = ", len(testIdentities)*numberOfRequestsPerID)

	return testIdentities
}
