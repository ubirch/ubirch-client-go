package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

var (
	ErrAlreadyInitialized = errors.New("identity already registered")
)

type RegistrationPayload struct {
	Uid uuid.UUID `json:"uuid"`
	Pwd string    `json:"password"`
}

type InitializeIdentity func(uid uuid.UUID, auth string) (csr []byte, err error)

func Register(registerAuth string, initialize InitializeIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h.XAuthHeader) != registerAuth {
			log.Warnf("unauthorized registration attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		idPayload, err := identityFromBody(r)
		if err != nil {
			log.Warnf("unsuccessful registration attempt: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		uid := idPayload.Uid

		csr, err := initialize(uid, idPayload.Pwd)
		if err != nil {
			switch err {
			case ErrAlreadyInitialized:
				h.Error(uid, w, err, http.StatusConflict)
			default:
				log.Errorf("%s: identity registration failed: %v", uid, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		h.SendResponse(w, h.HTTPResponse{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": {h.BinType},
			},
			Content: csr,
		})

		prom.IdentityCreationCounter.Inc()
	}
}

func identityFromBody(r *http.Request) (RegistrationPayload, error) {
	contentType := h.ContentType(r.Header)
	if contentType != h.JSONType {
		return RegistrationPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", h.JSONType, contentType)
	}

	var payload RegistrationPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return RegistrationPayload{}, err
	}
	if payload.Uid == uuid.Nil {
		return RegistrationPayload{}, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) == 0 {
		return RegistrationPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
