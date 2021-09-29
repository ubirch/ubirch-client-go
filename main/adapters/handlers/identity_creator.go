package handlers

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

type IdentityCreator struct {
	auth string
}

type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

type StoreIdentity func(uid uuid.UUID, auth string) (csr []byte, err error)
type CheckIdentityExists func(uid uuid.UUID) (bool, error)

func NewIdentityCreator(auth string) IdentityCreator {
	return IdentityCreator{auth: auth}
}

func (i *IdentityCreator) Put(storeId StoreIdentity, idExists CheckIdentityExists) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(h.XAuthHeader)
		if authHeader != i.auth {
			log.Warnf("unauthorized registration attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		idPayload, err := IdentityFromBody(r)
		if err != nil {
			log.Warn(err)
			h.Respond400(w, err.Error())
			return
		}

		uid, err := uuid.Parse(idPayload.Uid)
		if err != nil {
			log.Warnf("%s: %v", idPayload.Uid, err)
			h.Respond400(w, err.Error())
			return
		}

		exists, err := idExists(uid)
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if exists {
			h.Error(uid, w, fmt.Errorf("identity already registered"), http.StatusConflict)
			return
		}

		timer := prometheus.NewTimer(prom.IdentityCreationDuration)
		csr, err := storeId(uid, idPayload.Pwd)
		timer.ObserveDuration()
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

		w.Header().Set(h.HeaderContentType, h.BinType)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(csrPEM)
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}

		prom.IdentityCreationCounter.Inc()
	}
}

func IdentityFromBody(r *http.Request) (*IdentityPayload, error) {
	contentType := r.Header.Get(h.HeaderContentType)
	if contentType != h.JSONType {
		return nil, fmt.Errorf("invalid content-type: expected %s, got %s", h.JSONType, contentType)
	}
	if r.Body == nil {
		return nil, fmt.Errorf("empty body")
	}

	var payload IdentityPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if len(payload.Uid) == 0 {
		return nil, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) == 0 {
		return nil, fmt.Errorf("empty password")
	}
	return &payload, nil
}
