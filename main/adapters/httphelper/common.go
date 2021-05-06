package httphelper

import (
	"fmt"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	BackendRequestTimeout = 10 * time.Second // time after which requests to the ubirch backend will be canceled
	GatewayTimeout        = 20 * time.Second // time after which the client sends a 504 response if no timely response could be produced
	ShutdownTimeout       = 25 * time.Second // time after which the server will be shut down forcefully if graceful shutdown did not happen before
	ReadTimeout           = 1 * time.Second  // maximum duration for reading the entire request -> low since we only expect requests with small content
	WriteTimeout          = 30 * time.Second // time after which the connection will be closed if response was not written -> this should never happen
	IdleTimeout           = 60 * time.Second // time to wait for the next request when keep-alives are enabled
)

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
func GetUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, vars.UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}



func ReadBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}

func IsHashRequest(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, vars.HashEndpoint)
}
