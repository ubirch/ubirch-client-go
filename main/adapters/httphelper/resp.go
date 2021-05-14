package httphelper

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

func Health(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", server)
		w.Header().Set(HeaderContentType, MimeTextPlain)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(http.StatusText(http.StatusOK)))
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}
	}
}

func Ok(w http.ResponseWriter, rsp string) {
	w.Header().Set(HeaderContentType, MimeTextPlain)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(rsp))
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

func HttpFailed(StatusCode int) bool {
	return !HttpSuccess(StatusCode)
}

func HttpSuccess(StatusCode int) bool {
	return StatusCode >= 200 && StatusCode < 300
}
