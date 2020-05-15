package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

const (
	UUIDKey  = "uuid"
	BinType  = "application/octet-stream"
	JSONType = "application/json"
	HashLen  = 32
)

type Sha256Sum [HashLen]byte

type ServerEndpoint struct {
	Path           string
	MessageHandler chan HTTPMessage
	RequiresAuth   bool
	AuthTokens     map[string]string
}

type HTTPMessage struct {
	ID       uuid.UUID
	Hash     Sha256Sum
	Response chan HTTPResponse
}

type HTTPResponse struct {
	Code    int
	Header  map[string][]string
	Content []byte
}

func logError(err error) {
	log.Printf("HTTP SERVER ERROR: %s", err)
}

// helper function to get "content-type" from headers
func ContentType(r *http.Request) string {
	return strings.ToLower(r.Header.Get("content-type"))
}

// make sure request has correct content-type
func assertContentType(w http.ResponseWriter, r *http.Request, expectedType string) error {
	if ContentType(r) != expectedType {
		err := fmt.Sprintf("Wrong content-type. Expected \"%s\"", expectedType)
		http.Error(w, err, http.StatusBadRequest)
		return fmt.Errorf(err)
	}

	return nil
}

// helper function to get "x-auth-token" from headers
func XAuthToken(r *http.Request) string {
	return r.Header.Get("x-auth-token")
}

// get UUID from request URL and check auth token
func checkAuth(w http.ResponseWriter, r *http.Request, AuthTokens map[string]string) (uuid.UUID, error) {
	// get UUID from URL
	urlParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(urlParam)
	if err != nil {
		err := fmt.Sprintf("unable to parse \"%s\" as UUID: %s", urlParam, err)
		http.Error(w, err, http.StatusNotFound)
		return uuid.Nil, fmt.Errorf(err)
	}

	// check if UUID is known
	idAuthToken, exists := AuthTokens[id.String()]
	if !exists {
		err := fmt.Sprintf("unknown UUID \"%s\"", id.String())
		http.Error(w, err, http.StatusNotFound)
		return uuid.Nil, fmt.Errorf(err)
	}

	// check authorization
	if XAuthToken(r) != idAuthToken {
		err := "invalid \"X-Auth-Token\""
		http.Error(w, err, http.StatusUnauthorized)
		return uuid.Nil, fmt.Errorf(err)
	}

	return id, err
}

func getSortedCompactJSON(w http.ResponseWriter, data []byte) ([]byte, error) {
	var reqDump interface{}
	var compactSortedJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		err := fmt.Sprintf("unable to parse request body: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}
	// json.Marshal sorts the keys
	sortedJson, err := json.Marshal(reqDump)
	if err != nil {
		err := fmt.Sprintf("unable to serialize json object: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}
	// remove spaces and newlines
	err = json.Compact(&compactSortedJson, sortedJson)
	if err != nil {
		err := fmt.Sprintf("unable to compact json object: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return nil, fmt.Errorf(err)
	}

	return compactSortedJson.Bytes(), err
}

func getHash(w http.ResponseWriter, r *http.Request, isHash bool) (Sha256Sum, error) {
	var hash Sha256Sum

	// read request body
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		err := fmt.Sprintf("unable to read request body: %v", err)
		http.Error(w, err, http.StatusBadRequest)
		return hash, fmt.Errorf(err)
	}

	if ContentType(r) == JSONType {
		// generate a sorted compact rendering of the json formatted request body
		data, err = getSortedCompactJSON(w, data)
		if err != nil {
			return hash, err
		}
		// TODO
		//// only log original data if in debug-mode and never on production stage
		//if Debug && Env != PROD_STAGE {
		//	log.Printf("compact sorted json (go): %s", string(data))
		//}
	}

	if !isHash {
		hash = sha256.Sum256(data)
	} else {
		if len(data) != HashLen {
			err := fmt.Sprintf("invalid hash size. expected %d bytes, got %d (%s)", HashLen, len(data), data)
			http.Error(w, err, http.StatusBadRequest)
			return hash, fmt.Errorf(err)
		}
		copy(hash[:], data)
	}

	return hash, err
}

// blocks until response is received and forwards it to sender	// TODO go
func forwardBackendResponse(w http.ResponseWriter, respChan chan HTTPResponse) {
	resp := <-respChan
	w.WriteHeader(resp.Code)
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	_, err := w.Write(resp.Content)
	if err != nil {
		logError(fmt.Errorf("unable to write response: %s", err))
	}
}

func (srv *ServerEndpoint) handleRequest(w http.ResponseWriter, r *http.Request, isHash bool) {
	var id uuid.UUID
	var err error

	if srv.RequiresAuth {
		id, err = checkAuth(w, r, srv.AuthTokens)
		if err != nil {
			logError(err)
			return
		}
	}

	hash, err := getHash(w, r, isHash)
	if err != nil {
		logError(err)
		return
	}

	// create HTTPMessage with individual response channel for each request
	respChan := make(chan HTTPResponse)

	// submit message for singing
	srv.MessageHandler <- HTTPMessage{ID: id, Hash: hash, Response: respChan}

	// wait for response from ubirch backend to be forwarded
	forwardBackendResponse(w, respChan)
}

func (srv *ServerEndpoint) handleRequestHash(w http.ResponseWriter, r *http.Request) {
	err := assertContentType(w, r, BinType)
	if err != nil {
		logError(err)
		return
	}

	srv.handleRequest(w, r, true)
}

func (srv *ServerEndpoint) handleRequestJSON(w http.ResponseWriter, r *http.Request) {
	err := assertContentType(w, r, JSONType)
	if err != nil {
		logError(err)
		return
	}

	srv.handleRequest(w, r, false)
}

type HTTPServer struct {
	Router   *chi.Mux
	TLS      bool
	CertFile string
	KeyFile  string
}

func (srv *HTTPServer) AddEndpoint(endpoint ServerEndpoint) {
	srv.Router.Post(endpoint.Path, endpoint.handleRequestJSON)
	srv.Router.Post(endpoint.Path+"/hash", endpoint.handleRequestHash)
}

func (srv *HTTPServer) Serve(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	server := &http.Server{
		Addr:         ":8080",
		Handler:      srv.Router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  75 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Printf("shutting down http server")
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Failed to gracefully shutdown server: %s", err)
		}
	}()

	log.Printf("starting HTTP service")

	var err error
	if srv.TLS {
		log.Printf("TLS enabled")
		err = server.ListenAndServeTLS(srv.CertFile, srv.KeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("error starting HTTP service: %v", err)
	}
}

func InternalServerError(message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(http.StatusInternalServerError)
	}
	log.Printf(message)
	return HTTPResponse{
		Code:    http.StatusInternalServerError,
		Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		Content: []byte(message),
	}
}
