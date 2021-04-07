package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type SigningResponse struct {
	Error     string       `json:"error,omitempty"`
	Operation string       `json:"operation,omitempty"`
	Hash      []byte       `json:"hash,omitempty"`
	UPP       []byte       `json:"upp,omitempty"`
	Response  HTTPResponse `json:"response,omitempty"`
	RequestID string       `json:"requestID,omitempty"`
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

func sendRequests(id string, auth string, ccChan chan<- []byte, wg *sync.WaitGroup) {
	HTTPclient := &http.Client{Timeout: 25 * time.Second}
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

func sendRequest(HTTPclient *http.Client, clientURL string, header http.Header, hash []byte) (SigningResponse, error) {
	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
	if err != nil {
		return SigningResponse{}, err
	}

	req.Header = header

	resp, err := HTTPclient.Do(req)
	if err != nil {
		return SigningResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return SigningResponse{}, fmt.Errorf(resp.Status)
	}

	clientResponse := SigningResponse{}
	err = json.NewDecoder(resp.Body).Decode(&clientResponse)
	if err != nil {
		return SigningResponse{}, err
	}

	return clientResponse, nil
}
