package api

import (
	"bytes"
	"context"
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

const keyUUID = "uuid"

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(w http.ResponseWriter, error string, code int) {
	log.Printf("HTTP server error: " + error)
	http.Error(w, error, code)
}

// helper function to get "content-type" from headers
func ContentType(r *http.Request) string {
	return strings.ToLower(r.Header.Get("content-type"))
}

// helper function to get "x-auth-token" from headers
func XAuthToken(r *http.Request) string {
	return r.Header.Get("x-auth-token")
}

func checkAuth(w http.ResponseWriter, r *http.Request, AuthTokens map[string]string) (uuid.UUID, error) {
	// get UUID from URL
	urlParam := chi.URLParam(r, keyUUID)
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

// blocks until response is received and forwards it to sender
func forwardResponse(respChan chan HTTPResponse, w http.ResponseWriter) {
	resp := <-respChan
	w.WriteHeader(resp.Code)
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Printf("HTTP server encountered error writing response: %s", err)
	}
}

type HTTPServer struct {
	MessageHandler chan HTTPMessage
	AuthTokens     map[string]string
}

type HTTPMessage struct {
	ID              uuid.UUID
	Msg             []byte
	IsAlreadyHashed bool
	Response        chan HTTPResponse
}

type HTTPResponse struct {
	Code    int
	Header  map[string][]string
	Content []byte
}

func (srv *HTTPServer) handleRequestHash(w http.ResponseWriter, r *http.Request) {
	// get UUID from URL
	id, err := checkAuth(w, r, srv.AuthTokens)
	if err != nil {
		log.Printf("HTTP SERVER ERROR: %s", err)
		return
	}

	// make sure request body is of correct type
	expectedType := "application/octet-stream"
	if ContentType(r) != expectedType {
		Error(w, fmt.Sprintf("Wrong content-type. Expected \"%s\"", expectedType), http.StatusBadRequest)
		return
	}

	// read request body
	message, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Error(w, fmt.Sprintf("unable to read request body: %v", err), http.StatusBadRequest)
		return
	}

	respChan := make(chan HTTPResponse)
	srv.MessageHandler <- HTTPMessage{ID: id, Msg: message, IsAlreadyHashed: true, Response: respChan}

	// wait for response from ubirch backend to be forwarded
	forwardResponse(respChan, w)
}

func (srv *HTTPServer) handleRequestData(w http.ResponseWriter, r *http.Request) {
	id, err := checkAuth(w, r, srv.AuthTokens)
	if err != nil {
		log.Printf("HTTP SERVER ERROR: %s", err)
		return
	}

	// make sure request body is of correct type
	expectedType := "application/json"
	if ContentType(r) != expectedType {
		Error(w, fmt.Sprintf("Wrong content-type. Expected \"%s\"", expectedType), http.StatusBadRequest)
		return
	}

	// read request body
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Error(w, fmt.Sprintf("unable to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// generate a sorted compact rendering of the json formatted request body
	var reqDump interface{}
	var compactSortedJson bytes.Buffer
	err = json.Unmarshal(reqBody, &reqDump)
	if err != nil {
		Error(w, fmt.Sprintf("unable to parse request body: %v", err), http.StatusBadRequest)
		return
	}
	// json.Marshal sorts the keys
	sortedJson, err := json.Marshal(reqDump)
	if err != nil {
		Error(w, fmt.Sprintf("unable to serialize json object: %v", err), http.StatusBadRequest)
		return
	}
	err = json.Compact(&compactSortedJson, sortedJson)
	if err != nil {
		Error(w, fmt.Sprintf("unable to compact json object: %v", err), http.StatusBadRequest)
		return
	}
	message := compactSortedJson.Bytes()

	// create HTTPMessage with individual response channel for each request
	respChan := make(chan HTTPResponse)
	srv.MessageHandler <- HTTPMessage{ID: id, Msg: message, IsAlreadyHashed: false, Response: respChan}

	// wait for response from ubirch backend to be forwarded
	forwardResponse(respChan, w)
}

func (srv *HTTPServer) Serve(ctx context.Context, wg *sync.WaitGroup, TLS bool, certFile string, keyFile string) {
	router := chi.NewMux()
	router.Post(fmt.Sprintf("/{%s}", keyUUID), srv.handleRequestData)
	router.Post(fmt.Sprintf("/{%s}/hash", keyUUID), srv.handleRequestHash)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
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

	go func() {
		defer wg.Done()

		log.Printf("starting HTTP service")
		var err error
		if TLS {
			log.Printf("TLS enabled")
			err = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("error starting HTTP service: %v", err)
		}
	}()
}
