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
	VerifyPath   = "verify"
	COSEPath     = "cbor"
	HashEndpoint = "hash"

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

type COSEService struct {
	*CoseSigner
	AuthTokens map[string]string
}

var _ Service = (*COSEService)(nil)

type VerificationService struct {
	*Verifier
}

var _ Service = (*VerificationService)(nil)

func (c *ChainingService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var err error

	msg := HTTPRequest{
		Operation:  chainHash,
		Response:   make(chan HTTPResponse),
		RequestCtx: r.Context(),
	}

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, c.AuthTokens)
	if err != nil {
		Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	err = c.submitForChaining(msg)
	if err != nil {
		log.Warnf("%s: %v", msg.ID, err)
		http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		return
	}

	resp, err := waitForResp(msg.Response, r.Context())
	if err != nil {
		log.Warnf("%s: %v", msg.ID, err)
		return
	}

	sendResponse(w, resp)
}

func (c *ChainingService) submitForChaining(msg HTTPRequest) error {
	select {
	case c.Jobs <- msg:
		return nil
	default: // do not accept any more requests if buffer is full
		return fmt.Errorf("resquest skipped due to overflowing request channel")
	}
}

func (s *SigningService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, s.AuthTokens)
	if err != nil {
		Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Operation, err = getOperation(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Sign(msg)
	sendResponse(w, resp)
}

func (v *VerificationService) handleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := getHash(r)
	if err != nil {
		Error(uuid.Nil, w, err, http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	sendResponse(w, resp)
}

func (c *COSEService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, c.AuthTokens)
	if err != nil {
		Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	payload, hash, err := c.getPayloadAndCBORHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	msg.Hash = hash

	resp := c.Sign(msg)

	if !isHashRequest(r) { // if we know the original data, we can insert it to the COSE_Sign1 object
		err = c.InsertPayloadToCOSE(&resp.Content, payload)
		if err != nil {
			log.Warnf("%s: %v", msg.ID, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if ENV != PROD_STAGE { // never log original data on prod
			log.Debugf("%s: signed COSE with original data: %x", msg.ID, resp.Content)
		}
	}

	sendResponse(w, resp)
}

func (c *COSEService) getPayloadAndCBORHash(r *http.Request) ([]byte, Sha256Sum, error) {
	rBody, err := readBody(r)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	if isHashRequest(r) { // request contains hash
		hash, err := getHashFromHashRequest(r.Header, rBody)
		return nil, hash, err
	} else { // request contains original data
		if ContentType(r.Header) != BinType {
			return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for original data: expected \"%s\"", BinType)
		}
		hash, err := c.GetSigStructDigest(rBody)
		return rBody, hash, err
	}
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(uid uuid.UUID, w http.ResponseWriter, err error, code int) {
	log.Warnf("%s: %v", uid, err)
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
		return "", fmt.Errorf("unknown UUID")
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

func readBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}

func isHashRequest(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, HashEndpoint)
}

// getHash returns the hash from the request body
func getHash(r *http.Request) (Sha256Sum, error) {
	rBody, err := readBody(r)
	if err != nil {
		return Sha256Sum{}, err
	}

	if isHashRequest(r) { // request contains hash
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

		if ENV != PROD_STAGE { // never log original data on prod
			log.Debugf("sorted compact JSON: %s", string(data))
		}
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
	sortedJson, err := jsonMarshal(reqDump)
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

func jsonMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
}

// wait for response or context cancel
// returns the response, if response comes first, or ctx.Err(), if context was canceled first
func waitForResp(msgResp <-chan HTTPResponse, ctx context.Context) (HTTPResponse, error) {
	select {
	case resp := <-msgResp:
		return resp, nil
	case <-ctx.Done():
		return HTTPResponse{}, ctx.Err()
	}
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
