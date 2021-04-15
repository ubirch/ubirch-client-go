package main

import (
	"encoding/json"
	"os"

	log "github.com/sirupsen/logrus"
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

	return testIdentities
}
