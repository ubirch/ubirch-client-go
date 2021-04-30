package httphelper

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

func EmptyOk(w http.ResponseWriter) {
	w.Header().Set(HeaderContentType, MimeTextPlain)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte{})
	if err != nil {
		log.Errorf("unable to write response: %s", err)
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
