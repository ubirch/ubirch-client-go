package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
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

	testIdentities := getTestIdentities(numberOfTestIDs)
	log.Infof("%d identities, %d requests each", len(testIdentities), numberOfRequestsPerID)
	log.Infof(" = = = => sending %d requests <= = = = ", len(testIdentities)*numberOfRequestsPerID)

	cc := chainChecker{signatures: make(map[string][]byte, numberOfTestIDs)}
	ccChan := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())
	go cc.checkChain(ccChan, cancel)

	start := time.Now()

	for uid, auth := range testIdentities {
		sendRequests(uid, auth, ccChan, &wg)
	}

	log.Infof(" = = = => requests sent after %7.3f seconds <= = = = ", time.Since(start).Seconds())
	wg.Wait()
	close(ccChan)
	<-ctx.Done()
	log.Infof(" = = = => requests done after %7.3f seconds <= = = = ", time.Since(start).Seconds())
}

func sendRequests(id string, auth string, ccChan chan<- []byte, wg *sync.WaitGroup) {
	HTTPclient := &http.Client{Timeout: 65 * time.Second}
	clientURL := clientBaseURL + id + "/hash"
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	for i := 1; i <= numberOfRequestsPerID; i++ {
		wg.Add(1)
		go sendAndCheckResponse(HTTPclient, clientURL, header, ccChan, wg)

		time.Sleep(time.Second / numberOfRequestsPerID)
	}
}

func sendAndCheckResponse(HTTPclient *http.Client, clientURL string, header http.Header, ccChan chan<- []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	hash := make([]byte, 32)
	_, err := rand.Read(hash)
	if err != nil {
		log.Error(err)
		return
	}

	resp, err := sendRequest(HTTPclient, clientURL, header, hash)
	if err != nil {
		log.Error(err)
		return
	}

	// check resp -> hash
	if !bytes.Equal(hash, resp.Hash) {
		log.Error("HASH MISMATCH")
	}
	// check resp -> chain
	ccChan <- resp.UPP
}

func sendRequest(HTTPclient *http.Client, clientURL string, header http.Header, hash []byte) (signingResponse, error) {
	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
	if err != nil {
		return signingResponse{}, err
	}

	req.Header = header

	resp, err := HTTPclient.Do(req)
	if err != nil {
		return signingResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return signingResponse{}, fmt.Errorf(resp.Status)
	}

	clientResponse := signingResponse{}
	err = json.NewDecoder(resp.Body).Decode(&clientResponse)
	if err != nil {
		return signingResponse{}, err
	}

	return clientResponse, nil
}
