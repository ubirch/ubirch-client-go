package http_server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

// SendResponse forwards a response to the client
func SendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

type errorLog struct {
	Uid    uuid.UUID `json:"uuid,omitempty"`
	Path   string    `json:"path,omitempty"`
	Error  string    `json:"error,omitempty"`
	Status string    `json:"status,omitempty"`
}

// ClientError is a wrapper for http.Error that additionally logs uuid, request URL path, error message and status
// with logging level "warning"
func ClientError(uid uuid.UUID, r *http.Request, w http.ResponseWriter, errMsg string, code int) {
	errLog, _ := json.Marshal(errorLog{
		Uid:    uid,
		Path:   r.URL.Path,
		Error:  errMsg,
		Status: fmt.Sprintf("%d %s", code, http.StatusText(code)),
	})
	log.Warnf("ClientError: %s", errLog)
	http.Error(w, errMsg, code)
}

// ServerError is a wrapper for http.Error that additionally logs uuid, request URL path, error message and status
// with logging level "error". The error message is not sent to the client.
func ServerError(uid uuid.UUID, r *http.Request, w http.ResponseWriter, errMsg string, code int) {
	errLog, _ := json.Marshal(errorLog{
		Uid:    uid,
		Path:   r.URL.Path,
		Error:  errMsg,
		Status: fmt.Sprintf("%d %s", code, http.StatusText(code)),
	})
	log.Errorf("ServerError: %s", errLog)
	http.Error(w, http.StatusText(code), code)
}

// Health is a liveness probe.
func Health(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", TextType)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(append([]byte(http.StatusText(http.StatusOK)), '\n'))
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}
	}
}

// Ready is a readiness probe.
func Ready(server string, readinessChecks []func(ctx context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK

		for _, isReady := range readinessChecks {
			if err := isReady(r.Context()); err != nil {
				log.Warnf("readiness probe failed: %v", err)
				status = http.StatusServiceUnavailable
				break
			}
		}

		w.Header().Set("Server", server)
		w.Header().Set("Content-Type", TextType)
		w.WriteHeader(status)
		_, err := w.Write(append([]byte(http.StatusText(status)), '\n'))
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}
	}
}
