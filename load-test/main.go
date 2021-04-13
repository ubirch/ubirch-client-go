package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	clientBaseURL          = "http://localhost:8080/"
	configFile             = "config.json"
	numberOfTestIDs        = 100
	numberOfRequestsPerID  = 10
	requestsPerSecondPerID = 4
)

func main() {
	t := setup()

	log.Infof("%d identities, %d requests each => sending [%d] requests", len(t.identities), numberOfRequestsPerID, len(t.identities)*numberOfRequestsPerID)
	log.Infof("%d requests per second per identity", requestsPerSecondPerID)

	start := time.Now()

	for uid, auth := range t.identities {
		t.wg.Add(1)
		go t.sendRequests(uid, auth)
	}

	t.wg.Wait()
	log.Infof(" = = = => requests done after %7.3f seconds <= = = = ", time.Since(start).Seconds())
	t.teardown()
}

func (t *testCtx) sendRequests(id string, auth string) {
	defer t.wg.Done()

	HTTPclient := &http.Client{Timeout: 65 * time.Second}
	clientURL := clientBaseURL + id + "/hash"
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	for i := 1; i <= numberOfRequestsPerID; i++ {
		t.wg.Add(1)
		go t.sendAndCheckResponse(HTTPclient, clientURL, header)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

func (t *testCtx) sendAndCheckResponse(HTTPclient *http.Client, clientURL string, header http.Header) {
	defer t.wg.Done()

	hash := make([]byte, 32)
	_, err := rand.Read(hash)
	if err != nil {
		log.Error(err)
		return
	}

	resp, err := t.sendRequest(HTTPclient, clientURL, header, hash)
	if err != nil {
		log.Error(err)
		return
	}

	// check resp -> hash
	if !bytes.Equal(hash, resp.Hash) {
		log.Error("HASH MISMATCH")
	}
	// check resp -> chain
	t.ccChan <- resp.UPP
}

func (t *testCtx) sendRequest(HTTPclient *http.Client, clientURL string, header http.Header, hash []byte) (signingResponse, error) {
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
		t.failChan <- resp.Status
		return signingResponse{}, fmt.Errorf(resp.Status)
	}

	clientResponse := signingResponse{}
	err = json.NewDecoder(resp.Body).Decode(&clientResponse)
	if err != nil {
		return signingResponse{}, err
	}

	return clientResponse, nil
}
