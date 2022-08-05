package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	urlpkg "net/url"
)

type Config struct {
	Url          string            `json:"url"`
	Devices      map[string]string `json:"devices"`
	RegisterAuth string            `json:"registerAuth"`
	url          *urlpkg.URL
}

func (c *Config) load() error {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

	flag.Parse()
	if len(*configFile) == 0 {
		*configFile = defaultConfigFile
	}
	log.Infof("loading config: %s", *configFile)

	fileHandle, err := os.Open(filepath.Clean(*configFile))
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		return fmt.Errorf("decoding config failed: %v", err)
	}

	if c.Url == "" {
		return fmt.Errorf("missing client base URL (\"url\") in config")
	}

	c.url, err = urlpkg.Parse(c.Url)
	if err != nil {
		return fmt.Errorf("client base URL could not be parsed: %v", err)
	}

	return nil
}

func (c *Config) initTestIdentities(sender *Sender) (testIdentities map[string]string, err error) {
	testIdentities = make(map[string]string, numberOfTestIDs)

	for uid, auth := range c.Devices {

		err = sender.register(*c.url, uid, auth, c.RegisterAuth)
		if err != nil {
			log.Fatal(err)
		}

		testIdentities[uid] = auth

		if len(testIdentities) == numberOfTestIDs {
			break
		}
	}

	return testIdentities, nil
}
