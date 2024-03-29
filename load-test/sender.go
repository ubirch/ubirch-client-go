package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	urlpkg "net/url"
)

type SigningResponse struct {
	Hash []byte
	UPP  []byte
}

type Sender struct {
	httpClient       *http.Client
	chainChecker     *ChainChecker
	statusCounter    map[string]int
	statusCounterMtx *sync.Mutex
	requestTimer     time.Duration
	requestCounter   int
	requestTimerMtx  *sync.Mutex
}

func NewSender() *Sender {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = httpConnectionPoolSize
	transport.MaxConnsPerHost = httpConnectionPoolSize
	transport.MaxIdleConnsPerHost = httpConnectionPoolSize

	return &Sender{
		httpClient: &http.Client{
			Timeout:   httpClientTimeoutSec * time.Second,
			Transport: transport,
		},
		chainChecker:     NewChainChecker(),
		statusCounter:    map[string]int{},
		statusCounterMtx: &sync.Mutex{},
		requestTimerMtx:  &sync.Mutex{},
	}
}

func (s *Sender) register(url urlpkg.URL, id, auth, registerAuth string) error {
	url.Path = path.Join(url.Path, "register")

	body, err := json.Marshal(map[string]string{
		"uuid":     id,
		"password": auth,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url.String(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", registerAuth)

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
		return fmt.Errorf("%s: registration returned: %s", id, resp.Status)
	}

	return nil
}

func (s *Sender) sendRequests(url urlpkg.URL, uid, auth string, offset time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()

	url.Path = path.Join(url.Path, uid, "hash")

	header := http.Header{}
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Auth-Token", auth)

	time.Sleep(offset)

	for i := 0; i < numberOfRequestsPerID; i++ {
		wg.Add(1)
		go s.sendAndCheckResponse(url.String(), header, wg)

		time.Sleep(time.Second / requestsPerSecondPerID)
	}
}

func (s *Sender) sendAndCheckResponse(clientURL string, header http.Header, wg *sync.WaitGroup) {
	defer wg.Done()

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
	s.chainChecker.UPPs <- resp.UPP
}

func (s *Sender) sendRequest(clientURL string, header http.Header, hash []byte) (SigningResponse, error) {
	req, err := http.NewRequest(http.MethodPost, clientURL, bytes.NewBuffer(hash))
	if err != nil {
		return SigningResponse{}, err
	}

	req.Header = header

	start := time.Now()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return SigningResponse{}, err
	}

	duration := time.Since(start)

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	s.countStatus(resp.Status)

	if resp.StatusCode == http.StatusOK {
		s.addTime(duration)
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		return SigningResponse{}, fmt.Errorf("%d: %s", resp.StatusCode, respBody)
	}

	clientResponse := SigningResponse{}
	err = json.NewDecoder(resp.Body).Decode(&clientResponse)
	if err != nil {
		return SigningResponse{}, err
	}

	return clientResponse, nil
}

func (s *Sender) countStatus(status string) {
	s.statusCounterMtx.Lock()
	s.statusCounter[status] += 1
	s.statusCounterMtx.Unlock()
}

func (s *Sender) addTime(dur time.Duration) {
	s.requestTimerMtx.Lock()
	s.requestTimer += dur
	s.requestCounter += 1
	s.requestTimerMtx.Unlock()
}

func (s *Sender) getAvgRequestDuration() time.Duration {
	if s.requestCounter == 0 {
		return 0
	}
	return s.requestTimer / time.Duration(s.requestCounter)
}
