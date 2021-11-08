package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Devices      map[string]string `json:"devices"`
	RegisterAuth string            `json:"registerAuth"`
}

func (c *Config) Load(filename string) error {
	fileHandle, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	return json.NewDecoder(fileHandle).Decode(c)
}

func (c *Config) GetTestIdentities() map[string]string {
	testIdentities := make(map[string]string, numberOfTestIDs)

	for uid, auth := range c.Devices {
		testIdentities[uid] = auth
		if len(testIdentities) == numberOfTestIDs {
			break
		}
	}

	return testIdentities
}
