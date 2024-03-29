package http_server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

type RegistrationPayload struct {
	Uid uuid.UUID `json:"uuid"`
	Pwd string    `json:"password"`
}

type InitializeIdentity func(uid uuid.UUID, auth string) (csr []byte, err error)

func Register(auth string, initialize InitializeIdentity) http.HandlerFunc {
	if len(auth) == 0 {
		panic("missing auth token for identity registration endpoint")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if AuthToken(r.Header) != auth {
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

		timer := prometheus.NewTimer(prom.IdentityCreationDuration)
		csr, err := initialize(idPayload.Uid, idPayload.Pwd)
		timer.ObserveDuration()
		if err != nil {
			switch err {
			case ErrAlreadyInitialized:
				ClientError(idPayload.Uid, r, w, err.Error(), http.StatusConflict)
			default:
				ServerError(idPayload.Uid, r, w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		SendResponse(w, HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {BinType}},
			Content:    csr,
		})

		prom.IdentityCreationCounter.Inc()
	}
}

func identityFromBody(r *http.Request) (RegistrationPayload, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return RegistrationPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", JSONType, contentType)
	}

	var payload RegistrationPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return RegistrationPayload{}, fmt.Errorf("could not decode registration payload JSON: %v", err)
	}
	if payload.Uid == uuid.Nil {
		return RegistrationPayload{}, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) == 0 {
		return RegistrationPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
