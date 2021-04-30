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

type Sender struct {
	testCtx    *TestCtx
	httpClient *http.Client
}

func NewSender(testCtx *TestCtx) *Sender {
	return &Sender{
		testCtx:    testCtx,
		httpClient: &http.Client{Timeout: 25 * time.Second},
	}
}

func (s *Sender) register(id string, auth string, registerAuth string) error {
	url := baseURL1 + "register"

	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("X-Auth-Token", registerAuth)

	registrationData := map[string]string{
		"uuid":     id,
		"password": auth,
	}

	body, err := json.Marshal(registrationData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header = header

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Warnf("%s: registration returned: %s", id, resp.Status)
	} else {
		log.Infof("registered new identity: %s", id)
	}

	return nil
}

func (s *Sender) sendRequests(id string, auth string) {
	defer s.testCtx.wg.Done()

	url1 := baseURL1 + id + "/hash"
	url2 := baseURL2 + id + "/hash"
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	for i := 1; i <= numberOfRequestsPerID/2; i++ {
		s.testCtx.wg.Add(2)
		go s.sendAndCheckResponse(url1, header)
		go s.sendAndCheckResponse(url2, header)

		time.Sleep(2 * time.Second / requestsPerSecondPerID)
	}
}

func (s *Sender) sendAndCheckResponse(url string, header http.Header) {
	defer s.testCtx.wg.Done()

	hash := make([]byte, 32)
	_, err := rand.Read(hash)
	if err != nil {
		log.Error(err)
		return
	}

	resp, err := s.sendRequest(url, header, hash)
	if err != nil {
		log.Error(err)
		return
	}

	// check resp -> hash
	if !bytes.Equal(hash, resp.Hash) {
		log.Error("HASH MISMATCH")
	}
	// check resp -> chain
	s.testCtx.chainChecker.UPPs <- resp.UPP
}

func (s *Sender) sendRequest(url string, header http.Header, hash []byte) (SigningResponse, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(hash))
	if err != nil {
		return SigningResponse{}, err
	}

	req.Header = header

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return SigningResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		s.testCtx.failCounter.StatusCodes <- resp.Status
		return SigningResponse{}, fmt.Errorf(resp.Status)
	}

	clientResponse := SigningResponse{}
	err = json.NewDecoder(resp.Body).Decode(&clientResponse)
	if err != nil {
		return SigningResponse{}, err
	}

	return clientResponse, nil
}
