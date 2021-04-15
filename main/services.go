package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	CBORType = "application/cbor"

	HexEncoding = "hex"

	HashLen = 32
)

type Sha256Sum [HashLen]byte

type HTTPRequest struct {
	ID   uuid.UUID
	Auth string
	Hash Sha256Sum
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type ChainingService struct {
	Jobs       map[string]chan ChainingRequest
	AuthTokens map[string]string
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

type ChainingRequest struct {
	HTTPRequest
	ResponseChan chan HTTPResponse
	RequestCtx   context.Context
}

type SigningService struct {
	*Signer
	AuthTokens map[string]string
}

var _ Service = (*SigningService)(nil)

type SigningRequest struct {
	HTTPRequest
	Operation operation
}

type COSEService struct {
	*CoseSigner
	AuthTokens map[string]string
}

var _ Service = (*COSEService)(nil)

type CBORRequest struct {
	HTTPRequest
	Payload []byte
}

type VerificationService struct {
	*Verifier
}

var _ Service = (*VerificationService)(nil)

func (c *ChainingService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var err error

	msg := ChainingRequest{
		ResponseChan: make(chan HTTPResponse),
		RequestCtx:   r.Context(),
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

	requestChan, found := c.Jobs[msg.ID.String()]
	if !found {
		Error(msg.ID, w, fmt.Errorf("chaining not supported for identity"), http.StatusForbidden)
		return
	}

	err = submitForChaining(requestChan, msg)
	if err != nil {
		log.Warnf("%s: %v", msg.ID, err)
		http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		return
	}

	resp, err := waitForResp(msg.ResponseChan, r.Context())
	if err != nil {
		log.Warnf("%s: %v", msg.ID, err)
		return
	}

	sendResponse(w, resp)
}

func submitForChaining(requestChan chan<- ChainingRequest, msg ChainingRequest) error {
	select {
	case requestChan <- msg:
		return nil
	default: // do not accept any more requests if buffer is full
		return fmt.Errorf("resquest skipped due to overflowing request channel")
	}
}

func (s *SigningService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg SigningRequest
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
	var msg CBORRequest
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

	payload, hash, err := c.getPayloadAndHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}
	msg.Payload = payload
	msg.Hash = hash

	resp := c.Sign(msg)

	sendResponse(w, resp)
}

func (c *COSEService) getPayloadAndHash(r *http.Request) (payload []byte, hash Sha256Sum, err error) {
	rBody, err := readBody(r)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	if isHashRequest(r) { // request contains hash
		hash, err = getHashFromHashRequest(r.Header, rBody)
		return rBody, hash, err
	} else { // request contains original data
		return c.getPayloadAndHashFromDataRequest(r.Header, rBody)
	}
}

func (c *COSEService) getPayloadAndHashFromDataRequest(header http.Header, data []byte) (payload []byte, hash Sha256Sum, err error) {
	switch ContentType(header) {
	case JSONType:
		data, err = c.getCBORFromJSON(data)
		if err != nil {
			return nil, Sha256Sum{}, fmt.Errorf("unable to CBOR encode JSON object: %v", err)
		}
		log.Debugf("CBOR encoded JSON: %x", data)

		fallthrough
	case CBORType:
		toBeSigned, err := c.GetSigStructBytes(data)
		if err != nil {
			return nil, Sha256Sum{}, err
		}
		log.Debugf("toBeSigned: %x", toBeSigned)

		hash = sha256.Sum256(toBeSigned)
		return data, hash, err
	default:
		return nil, Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", CBORType, JSONType)
	}
}

func (c *COSEService) getCBORFromJSON(data []byte) ([]byte, error) {
	var reqDump interface{}

	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON request body: %v", err)
	}

	return c.encMode.Marshal(reqDump)
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

// helper function to get "Content-Transfer-Encoding" from request header
func ContentEncoding(header http.Header) string {
	return strings.ToLower(header.Get("Content-Transfer-Encoding"))
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
		return "", fmt.Errorf("invalid operation: "+
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
		log.Debugf("sorted compact JSON: %s", string(data))

		fallthrough
	case BinType:
		// hash original data
		return sha256.Sum256(data), nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", BinType, JSONType)
	}
}

func getHashFromHashRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case TextType:
		if ContentEncoding(header) == HexEncoding {
			data, err = hex.DecodeString(string(data))
			if err != nil {
				return Sha256Sum{}, fmt.Errorf("decoding hex encoded hash failed: %v (%s)", err, string(data))
			}
		} else {
			data, err = base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
			}
		}
		fallthrough
	case BinType:
		if len(data) != HashLen {
			return Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected %d bytes, got %d bytes", HashLen, len(data))
		}

		copy(hash[:], data)
		return hash, nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", BinType, TextType)
	}
}

func getSortedCompactJSON(data []byte) ([]byte, error) {
	var reqDump interface{}
	var sortedCompactJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON request body: %v", err)
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
