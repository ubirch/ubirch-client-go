package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
)

var (
	ErrUnknown = errors.New("unknown identity")
)

type GetCSR func(uid uuid.UUID) (csr []byte, err error)

func FetchCSR(auth string, get GetCSR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h.XAuthHeader) != auth {
			log.Warnf("unauthorized CSR request")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		uid, err := h.GetUUID(r)
		if err != nil {
			log.Warnf("FetchCSR: %v", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		csr, err := get(uid)
		if err != nil {
			switch err {
			case ErrUnknown:
				h.Error(uid, w, err, http.StatusNotFound)
			default:
				h.Error(uid, w, err, http.StatusInternalServerError)
			}
			return
		}

		h.SendResponse(w, h.HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {h.BinType}},
			Content:    csr,
		})
	}
}
