package http_server

import (
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
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(append(resp.Content, '\n'))
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

// Error is a wrapper for http.Error that additionally logs the uuid and error message to std.Output
func Error(uid uuid.UUID, w http.ResponseWriter, err error, code int) {
	log.Warnf("%s: %v", uid, err)
	http.Error(w, err.Error(), code)
}

func Health(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
func Ready(server string, readinessChecks []func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		status := http.StatusOK

		for _, isReady := range readinessChecks {
			if err := isReady(); err != nil {
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
