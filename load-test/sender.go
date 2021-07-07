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
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Sender) register(id string, auth string, registerAuth string) error {
	url := clientBaseURL + "/register"

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

	switch resp.StatusCode {
	case http.StatusOK:
		log.Infof("registered new identity: %s", id)
	case http.StatusConflict:
		log.Debugf("%s: identity already registered", id)
	default:
		log.Warnf("%s: registration returned: %s", id, resp.Status)
	}

	return nil
}

func (s *Sender) sendRequests(id string, auth string) {
	defer s.testCtx.wg.Done()

	clientURL := clientBaseURL + fmt.Sprintf("/%s/hash", id)
	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	for i := 0; i < numberOfRequestsPerID; i++ {
		s.testCtx.wg.Add(1)
		go s.sendAndCheckResponse(clientURL, header)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

func (s *Sender) sendAndCheckResponse(clientURL string, header http.Header) {
	defer s.testCtx.wg.Done()

	hash := make([]byte, 32)
	_, err := rand.Read(hash)
	if err != nil {
		log.Error(err)
		return
	}

	resp, err := s.sendRequest(clientURL, header, hash)
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

func (s *Sender) sendRequest(clientURL string, header http.Header, hash []byte) (SigningResponse, error) {
	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
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

	s.testCtx.statusCounter.StatusCodes <- resp.Status

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
