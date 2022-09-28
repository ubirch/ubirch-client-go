package http_server

import (
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type GetCSR func(uid uuid.UUID) (csr []byte, err error)

func FetchCSR(auth string, get GetCSR) http.HandlerFunc {
	if len(auth) == 0 {
		panic("missing auth token for CSR creation endpoint")
	}
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
				ClientError(uid, r, w, err.Error(), http.StatusNotFound)
			default:
				ServerError(uid, r, w, err.Error(), http.StatusInternalServerError)
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
