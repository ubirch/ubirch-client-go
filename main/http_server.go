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
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	UUIDKey      = "uuid"
	OperationKey = "operation"
	HashEndpoint = "/hash"
	BinType      = "application/octet-stream"
	TextType     = "text/plain"
	JSONType     = "application/json"
	HashLen      = 32
)

type Sha256Sum [HashLen]byte

type ServerEndpoint struct {
	Path         string
	Service      Service
	RequiresAuth bool
	AuthTokens   map[string]string
}

type HTTPRequest struct {
	ID        uuid.UUID
	Auth      []byte
	Hash      Sha256Sum
	Operation operation
	Response  chan HTTPResponse
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Headers    http.Header `json:"headers"`
	Content    []byte      `json:"content"`
}

type Service interface {
	handleRequest(w http.ResponseWriter, r *http.Request, msg HTTPRequest)
}

type AnchoringService struct {
	Signer
}

type HashOperationsService struct {
	Signer
}

type VerificationService struct {
	Verifier
}

func (service *AnchoringService) handleRequest(w http.ResponseWriter, r *http.Request, msg HTTPRequest) {
	msg.Operation = anchorHash

	// create HTTPRequest with individual response channel for each request
	msg.Response = make(chan HTTPResponse)

	// submit message for signing
	service.MessageHandler <- msg

	// wait for response from ubirch backend to be forwarded
	sendResponseChannel(w, msg.Response)
}

func (service *HashOperationsService) handleRequest(w http.ResponseWriter, r *http.Request, msg HTTPRequest) {
	var err error
	msg.Operation, err = getOperation(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	resp := service.handleSigningRequest(msg)
	sendResponse(w, resp)
}

func (service *VerificationService) handleRequest(w http.ResponseWriter, r *http.Request, msg HTTPRequest) {
	resp := service.verifyHash(msg.Hash[:])
	sendResponse(w, resp)
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(w http.ResponseWriter, err error, code int) {
	log.Error(err)
	http.Error(w, err.Error(), code)
}

// helper function to get "Content-Type" from request headers
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// helper function to get "X-Auth-Token" from request headers
func AuthToken(header http.Header) string {
	return header.Get("X-Auth-Token")
}

// get UUID parameter from request URL
func getUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to parse \"%s\" into a UUID: %s", uuidParam, err)
	}
	return id, nil
}

// get operation parameter from request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, OperationKey)
	switch operation(opParam) {
	case deleteHash, enableHash, disableHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("unsupported operation \"%s\"", opParam)
	}
}

func getHash(r *http.Request) (Sha256Sum, error) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return Sha256Sum{}, fmt.Errorf("unable to read request body: %v", err)
	}

	isHashRequest := strings.HasSuffix(r.URL.Path, HashEndpoint)
	if isHashRequest { // request contains hash
		return getHashFromHashRequest(r, data)
	} else { // request contains original data
		return getHashFromDataRequest(r, data)
	}
}

func getHashFromDataRequest(r *http.Request, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(r.Header) {
	case JSONType:
		data, err = getSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		// only log original data if in debug-mode
		log.Debugf("sorted compact JSON: %s", string(data))
	case BinType:
	default:
		return Sha256Sum{}, fmt.Errorf("wrong content-type for original data. expected \"%s\" or \"%s\"", BinType, JSONType)
	}

	// hash original data
	return sha256.Sum256(data), nil
}

func getHashFromHashRequest(r *http.Request, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(r.Header) {
	case TextType:
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
		}
	case BinType:
	default:
		return Sha256Sum{}, fmt.Errorf("wrong content-type for hash. expected \"%s\" or \"%s\"", BinType, TextType)
	}

	if len(data) != HashLen {
		return Sha256Sum{}, fmt.Errorf("invalid hash size. expected %d bytes, got %d bytes (%s)", HashLen, len(data), data)
	}

	copy(hash[:], data)
	return hash, nil
}

func JSONMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
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
	sortedJson, err := JSONMarshal(reqDump)
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

// blocks until response is received and forwards it to sender
func sendResponseChannel(w http.ResponseWriter, respChan chan HTTPResponse) {
	resp := <-respChan
	sendResponse(w, resp)
}

// forwards response to sender
func sendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Headers {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

// check if auth token from request header is correct.
// Returns error if UUID is unknown or auth token does not match.
func (endpnt *ServerEndpoint) checkAuth(r *http.Request, id uuid.UUID) ([]byte, error) {
	// check if UUID is known
	idAuthToken, exists := endpnt.AuthTokens[id.String()]
	if !exists || idAuthToken == "" {
		return nil, fmt.Errorf("unknown UUID \"%s\"", id)
	}

	// check auth token from request header
	headerAuthToken := AuthToken(r.Header)
	if idAuthToken != headerAuthToken {
		return nil, fmt.Errorf("invalid auth token")
	}

	return []byte(headerAuthToken), nil
}

func (endpnt *ServerEndpoint) getMsgFromRequest(w http.ResponseWriter, r *http.Request) (msg HTTPRequest, err error) {
	if endpnt.RequiresAuth {
		msg.ID, err = getUUID(r)
		if err != nil {
			Error(w, err, http.StatusNotFound)
			return msg, err
		}
		msg.Auth, err = endpnt.checkAuth(r, msg.ID)
		if err != nil {
			Error(w, err, http.StatusUnauthorized)
			return msg, err
		}
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return msg, err
	}

	return msg, nil
}

func (endpnt *ServerEndpoint) handleRequest(w http.ResponseWriter, r *http.Request) {
	msg, err := endpnt.getMsgFromRequest(w, r)
	if err != nil {
		return
	}

	endpnt.Service.handleRequest(w, r, msg)
}

func (endpnt *ServerEndpoint) handleOptions(w http.ResponseWriter, r *http.Request) {
	return
}

type HTTPServer struct {
	router   *chi.Mux
	addr     string
	TLS      bool
	certFile string
	keyFile  string
}

func NewRouter() *chi.Mux {
	return chi.NewMux()
}

func (srv *HTTPServer) SetUpCORS(allowedOrigins []string, debug bool) {
	srv.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		ExposedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
		Debug:            debug,
	}))

	log.Printf("CORS enabled")
	log.Debugf(" - Allowed Origins: %v", allowedOrigins)
}

func (srv *HTTPServer) AddEndpoint(endpoint ServerEndpoint) {
	hashEndpointPath := path.Join(endpoint.Path + HashEndpoint)

	srv.router.Post(endpoint.Path, endpoint.handleRequest)
	srv.router.Post(hashEndpointPath, endpoint.handleRequest)

	srv.router.Options(endpoint.Path, endpoint.handleOptions)
	srv.router.Options(hashEndpointPath, endpoint.handleOptions)
}

func (srv *HTTPServer) Serve(ctx context.Context) error {
	server := &http.Server{
		Addr:         srv.addr,
		Handler:      srv.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 75 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Printf("shutting down http server")
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns
		if err := server.Shutdown(ctx); err != nil {
			log.Warnf("Failed to gracefully shut down server: %s", err)
		}
	}()

	if srv.TLS {
		log.Printf("TLS enabled")
		log.Debugf(" - Cert: %s", srv.certFile)
		log.Debugf(" -  Key: %s", srv.keyFile)
	}
	log.Printf("starting HTTP service")

	var err error
	if srv.TLS {
		err = server.ListenAndServeTLS(srv.certFile, srv.keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error starting HTTP service: %v", err)
	}
	return nil
}
