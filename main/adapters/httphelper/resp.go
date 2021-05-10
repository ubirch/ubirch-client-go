package httphelper

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

func Health(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", fmt.Sprintf("ubirch-go-client/%s", version))
		w.Header().Set(HeaderContentType, MimeTextPlain)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ok\n")
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
