package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	UUIDKey  = "uuid"
	BinType  = "application/octet-stream"
	TextType = "text/plain"
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
	Headers map[string][]string
	Content []byte
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(w http.ResponseWriter, err error, code int) {
	log.Error(err)
	http.Error(w, fmt.Sprint(err), code)
}

// helper function to get "Content-Type" from headers
func ContentType(r *http.Request) string {
	return strings.ToLower(r.Header.Get("Content-Type"))
}

// helper function to get "X-Auth-Token" from headers
func XAuthToken(r *http.Request) string {
	return r.Header.Get("X-Auth-Token")
}

// get UUID from request URL
func getUUID(r *http.Request) (uuid.UUID, error) {
	urlParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(urlParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to parse \"%s\" as UUID: %s", urlParam, err)
	}

	return id, nil
}

func getSortedCompactJSON(data []byte) ([]byte, error) {
	var reqDump interface{}
	var sortedCompactJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse request body: %v", err)
	}
	// json.Marshal sorts the keys
	sortedJson, err := json.Marshal(reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize json object: %v", err)
	}
	// remove spaces and newlines
	err = json.Compact(&sortedCompactJson, sortedJson)
	if err != nil {
		return nil, fmt.Errorf("unable to compact json object: %v", err)
	}

	return sortedCompactJson.Bytes(), nil
}

func getHash(r *http.Request, isHash bool) (Sha256Sum, error) {
	var hash Sha256Sum

	// read request body
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return Sha256Sum{}, fmt.Errorf("unable to read request body: %v", err)
	}

	contentType := ContentType(r)
	if !isHash { // request contains original data
		if contentType == JSONType {
			// generate a sorted compact rendering of the json formatted request body
			data, err = getSortedCompactJSON(data)
			if err != nil {
				return Sha256Sum{}, err
			}

			// only log original data if in debug-mode
			log.Debugf("sorted compact JSON: %s", string(data))

		} else if contentType != BinType {
			return Sha256Sum{}, fmt.Errorf("wrong content-type for original data. expected \"%s\" or \"%s\"", BinType, JSONType)
		}

		hash = sha256.Sum256(data)
	} else { // request contains hash
		if contentType == TextType {
			data, err = base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
			}
		} else if contentType != BinType {
			return Sha256Sum{}, fmt.Errorf("wrong content-type for hash. expected \"%s\" or \"%s\"", BinType, TextType)
		}

		if len(data) != HashLen {
			return Sha256Sum{}, fmt.Errorf("invalid hash size. expected %d bytes, got %d bytes (%s)", HashLen, len(data), data)
		}
		copy(hash[:], data)
	}

	return hash, err
}

// blocks until response is received and forwards it to sender
func forwardBackendResponse(w http.ResponseWriter, respChan chan HTTPResponse) {
	resp := <-respChan
	for k, v := range resp.Headers {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.Code)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

// check if auth token from request header is correct.
// Returns error if UUID is unknown or auth token does not match.
func (endpnt *ServerEndpoint) checkAuth(id uuid.UUID, authHeader string) error {
	// check if UUID is known
	idAuthToken, exists := endpnt.AuthTokens[id.String()]
	if !exists {
		return fmt.Errorf("unknown UUID \"%s\"", id.String())
	}

	// check auth token
	if authHeader != idAuthToken {
		return fmt.Errorf("invalid auth token")
	}

	return nil
}

func (endpnt *ServerEndpoint) handleRequest(w http.ResponseWriter, r *http.Request, isHash bool) {
	var id uuid.UUID
	var err error

	if endpnt.RequiresAuth {
		id, err = getUUID(r)
		if err != nil {
			Error(w, err, http.StatusNotFound)
			return
		}
		err = endpnt.checkAuth(id, XAuthToken(r))
		if err != nil {
			Error(w, err, http.StatusUnauthorized)
			return
		}
	}

	hash, err := getHash(r, isHash)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	// create HTTPMessage with individual response channel for each request
	respChan := make(chan HTTPResponse)

	// submit message for singing
	endpnt.MessageHandler <- HTTPMessage{ID: id, Hash: hash, Response: respChan}

	// wait for response from ubirch backend to be forwarded
	forwardBackendResponse(w, respChan)
}

func (endpnt *ServerEndpoint) handleRequestHash(w http.ResponseWriter, r *http.Request) {
	endpnt.handleRequest(w, r, true)
}

func (endpnt *ServerEndpoint) handleRequestOriginalData(w http.ResponseWriter, r *http.Request) {
	endpnt.handleRequest(w, r, false)
}

func (endpnt *ServerEndpoint) handleOptions(writer http.ResponseWriter, request *http.Request) {
	return
}

type HTTPServer struct {
	router   *chi.Mux
	certFile string
	keyFile  string
}

func NewRouter() *chi.Mux {
	return chi.NewMux()
}

func (srv *HTTPServer) SetUpCORS(allowedOrigins []string) {
	srv.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		ExposedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
		Debug:            true,
	}))

	log.Printf("CORS enabled")
	log.Debugf(" - Allowed Origins: %v", allowedOrigins)
}

func (srv *HTTPServer) AddEndpoint(endpoint ServerEndpoint) {
	srv.router.Post(endpoint.Path, endpoint.handleRequestOriginalData)
	srv.router.Post(endpoint.Path+"/hash", endpoint.handleRequestHash)

	srv.router.Options(endpoint.Path, endpoint.handleOptions)
	srv.router.Options(endpoint.Path+"/hash", endpoint.handleOptions)
}

func (srv *HTTPServer) Serve(ctx context.Context, enableTLS bool) error {
	server := &http.Server{
		Addr:         ":8080",
		Handler:      srv.router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  75 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Printf("shutting down http server")
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns
		if err := server.Shutdown(ctx); err != nil {
			log.Warnf("Failed to gracefully shut down server: %s", err)
		}
	}()

	log.Printf("starting HTTP service")

	var err error
	if enableTLS {
		log.Printf("TLS enabled")
		log.Debugf(" - Cert: %s", srv.certFile)
		log.Debugf(" -  Key: %s", srv.keyFile)
		err = server.ListenAndServeTLS(srv.certFile, srv.keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error starting HTTP service: %v", err)
	}
	return nil
}

func HTTPErrorResponse(code int, message string) HTTPResponse {
	if message == "" {
		message = http.StatusText(code)
	}
	log.Error(message)
	return HTTPResponse{
		Code:    code,
		Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		Content: []byte(message),
	}
}
