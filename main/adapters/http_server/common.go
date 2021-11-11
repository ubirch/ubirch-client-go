package http_server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	BackendRequestTimeout = 15 * time.Second // time after which requests to the ubirch backend will be canceled
	GatewayTimeout        = 45 * time.Second // time after which a 504 response will be sent if no timely response could be produced
	ShutdownTimeout       = 25 * time.Second // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout           = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout          = 60 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout           = 60 * time.Second // time to wait for the next request when keep-alives are enabled

	UUIDKey                = "uuid"
	OperationKey           = "operation"
	VerifyPath             = "/verify"
	HashEndpoint           = "/hash"
	RegisterEndpoint       = "/register"
	CSREndpoint            = "/csr"
	ActiveUpdateEndpoint   = "/device/updateActive"
	MetricsEndpoint        = "/metrics"
	LivenessCheckEndpoint  = "/healthz"
	ReadinessCheckEndpoint = "/readyz"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	XAuthHeader = "x-auth-token"

	HexEncoding = "hex"

	HashLen = 32
)

var (
	UUIDPath      = fmt.Sprintf("/{%s}", UUIDKey)
	OperationPath = fmt.Sprintf("/{%s}", OperationKey)
)

type HTTPRequest struct {
	ID   uuid.UUID
	Auth string
	Hash Sha256Sum
}

type Sha256Sum [HashLen]byte

// GetUUID returns the UUID parameter from the request URL
func GetUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}

func IsHashRequest(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, HashEndpoint)
}

// GetHash returns the hash from the request body
func GetHash(r *http.Request) (Sha256Sum, error) {
	rBody, err := ReadBody(r)
	if err != nil {
		return Sha256Sum{}, err
	}

	if IsHashRequest(r) { // request contains hash
		return getHashFromHashRequest(r.Header, rBody)
	} else { // request contains original data
		return getHashFromDataRequest(r.Header, rBody)
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

func getHashFromDataRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(header) {
	case JSONType:
		data, err = GetSortedCompactJSON(data)
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

func GetSortedCompactJSON(data []byte) ([]byte, error) {
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
