package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

// configuration of the device
type Config struct {
	Auth       string `json:"auth"`
	Password   string `json:"password"`
	KeyService string `json:"keyService"`
	Niomon     string `json:"niomon"`
	Data       string `json:"data"`
	Mqtt       struct {
		Address  string `json:"address"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
}

// read the configuration
func (c *Config) Load(filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, c)
	if err != nil {
		log.Fatalf("unable to read configuration %v", err)
		return err
	}

	log.Printf("configuration found")
	if c.Auth == "" {
		c.Auth = "ubirch"
	}
	return nil
}
