package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"net/http"
)

// Later we can add authenticator
type Globals struct {
	Config  config.Config
	Version string
}

type HTTPRequest struct {
	ID   uuid.UUID
	Auth string
	Hash Sha256Sum
}

type Sha256Sum [vars.HashLen]byte

// getHash returns the hash from the request body
func getHash(r *http.Request) (Sha256Sum, error) {
	rBody, err := h.ReadBody(r)
	if err != nil {
		return Sha256Sum{}, err
	}

	if h.IsHashRequest(r) { // request contains hash
		return getHashFromHashRequest(r.Header, rBody)
	} else { // request contains original data
		return getHashFromDataRequest(r.Header, rBody)
	}
}

func getHashFromDataRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch h.ContentType(header) {
	case vars.JSONType:
		data, err = GetSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		log.Debugf("sorted compact JSON: %s", string(data))

		fallthrough
	case vars.BinType:
		// hash original data
		return sha256.Sum256(data), nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", vars.BinType, vars.JSONType)
	}
}

func getHashFromHashRequest(header http.Header, data []byte) (hash Sha256Sum, err error) {
	switch h.ContentType(header) {
	case vars.TextType:
		if h.ContentEncoding(header) == vars.HexEncoding {
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
	case vars.BinType:
		if len(data) != vars.HashLen {
			return Sha256Sum{}, fmt.Errorf("invalid SHA256 hash size: "+
				"expected %d bytes, got %d bytes", vars.HashLen, len(data))
		}

		copy(hash[:], data)
		return hash, nil
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", vars.BinType, vars.TextType)
	}
}

// forwards response to sender
func sendResponse(w http.ResponseWriter, resp h.HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}