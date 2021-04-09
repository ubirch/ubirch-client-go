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

	"github.com/go-chi/chi"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	UUIDKey      = "uuid"
	OperationKey = "operation"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	HashLen = 32
)

type Sha256Sum [HashLen]byte

type HTTPRequest struct {
	ID         uuid.UUID
	Auth       string
	Hash       Sha256Sum
	Operation  operation
	Response   chan HTTPResponse
	RequestCtx context.Context
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type ChainingService struct {
	Jobs       chan HTTPRequest
	AuthTokens map[string]string
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

type SigningService struct {
	*Signer
	AuthTokens map[string]string
}

var _ Service = (*SigningService)(nil)

type CBORService struct {
	*CoseSigner
	AuthTokens map[string]string
}

var _ Service = (*CBORService)(nil)

type VerificationService struct {
	*Verifier
}

var _ Service = (*VerificationService)(nil)

func (service *ChainingService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, service.AuthTokens)
	if err != nil {
		Error(w, err, http.StatusUnauthorized)
		return
	}

	msg.Operation = chainHash

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	// create HTTPRequest with individual response channel for each request
	msg.Response = make(chan HTTPResponse)

	msg.RequestCtx = r.Context()

	// submit message for chaining
	select {
	case service.Jobs <- msg:
	default: // do not accept any more requests if buffer is full
		log.Warnf("%s: resquest skipped due to overflowing request channel", msg.ID)
		http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		return
	}

	// wait for response or context cancel
	select {
	case resp := <-msg.Response:
		sendResponse(w, resp)
	case <-r.Context().Done():
		log.Warnf("%s: %v", msg.ID, r.Context().Err())
	}
}

func (service *SigningService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, service.AuthTokens)
	if err != nil {
		Error(w, err, http.StatusUnauthorized)
		return
	}

	msg.Operation, err = getOperation(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	resp := service.Sign(msg)
	sendResponse(w, resp)
}

func (service *VerificationService) handleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	resp := service.verifyHash(hash[:])
	sendResponse(w, resp)
}

func (service *CBORService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, service.AuthTokens)
	if err != nil {
		Error(w, err, http.StatusUnauthorized)
		return
	}

	isHashRequest := strings.HasSuffix(r.URL.Path, HashEndpoint)
	if !isHashRequest {
		err = fmt.Errorf("CBOR requests not yet supported. Please use the '/cbor/hash' endpoint")
		Error(w, err, http.StatusNotImplemented)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	resp := service.Sign(msg)
	sendResponse(w, resp)
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(w http.ResponseWriter, err error, code int) {
	log.Error(err)
	http.Error(w, err.Error(), code)
}

// helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// helper function to get "X-Auth-Token" from request header
func AuthToken(header http.Header) string {
	return header.Get("X-Auth-Token")
}

// getUUID returns the UUID parameter from the request URL
func getUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}

// checkAuth checks the auth token from the request header and returns it if valid
// Returns error if UUID is unknown or auth token is invalid
func checkAuth(r *http.Request, id uuid.UUID, authTokens map[string]string) (string, error) {
	// check if UUID is known
	idAuthToken, exists := authTokens[id.String()]
	if !exists || idAuthToken == "" {
		return "", fmt.Errorf("unknown UUID: \"%s\"", id.String())
	}

	// check auth token from request header
	headerAuthToken := AuthToken(r.Header)
	if idAuthToken != headerAuthToken {
		return "", fmt.Errorf("invalid auth token")
	}

	return headerAuthToken, nil
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, OperationKey)
	switch operation(opParam) {
	case anchorHash, disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid update operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			anchorHash, disableHash, enableHash, deleteHash, opParam)
	}
}

// getHash returns the hash from the request body
func getHash(r *http.Request) (Sha256Sum, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return Sha256Sum{}, fmt.Errorf("unable to read request body: %v", err)
	}

	isHashRequest := strings.HasSuffix(r.URL.Path, HashEndpoint)
	if isHashRequest { // request contains hash
		return getHashFromHashRequest(r.Header, rBody)
	} else { // request contains original data
		return getHashFromDataRequest(r.Header, rBody)
	}
}

func getHashFromDataRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case JSONType:
		data, err = getSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		// only log original data if in debug-mode
		log.Debugf("sorted compact JSON: %s", string(data))
	case BinType:
		// do nothing
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", BinType, JSONType)
	}

	// hash original data
	return sha256.Sum256(data), nil
}

func getHashFromHashRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case TextType:
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
		}
	case BinType:
		// do nothing
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", BinType, TextType)
	}

	if len(data) != HashLen {
		return Sha256Sum{}, fmt.Errorf("invalid hash size: "+
			"expected %d bytes, got %d bytes", HashLen, len(data))
	}

	copy(hash[:], data)
	return hash, nil
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

func JSONMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
}

// forwards response to sender
func sendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}
