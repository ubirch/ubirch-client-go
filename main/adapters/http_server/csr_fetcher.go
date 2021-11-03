package http_server

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

var (
	ErrUnknown = errors.New("unknown identity")
)

type GetCSR func(uid uuid.UUID) (csr []byte, err error)

func FetchCSR(auth string, get GetCSR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if AuthToken(r.Header) != auth {
			log.Warnf("unauthorized CSR request")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		uid, err := GetUUID(r)
		if err != nil {
			log.Warnf("FetchCSR: %v", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		csr, err := get(uid)
		if err != nil {
			switch err {
			case ErrUnknown:
				Error(uid, w, err, http.StatusNotFound)
			default:
				log.Errorf("%s: %v", uid, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		SendResponse(w, HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {BinType}},
			Content:    csr,
		})
	}
}
