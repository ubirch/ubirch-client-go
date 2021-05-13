package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/logger"
	"github.com/ubirch/ubirch-client-go/main/vars"
	"net/http"
)

type Identity struct {
	globals Globals
}

type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

func NewIdentity(globals Globals) Identity {
	return Identity{globals: globals}
}

func (i *Identity) Put(storeId StoreIdentity, idExists CheckIdentityExists) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(h.XAuthHeader)
		if authHeader != i.globals.Config.RegisterAuth {
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

		csr, err := storeId(uid, idPayload.Pwd)
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		logger.AuditLogf("created identity with UUID %s", uid)

		w.Header().Set(h.HeaderContentType, vars.BinType)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(csr)
		if err != nil {
			log.Errorf("unable to write response: %s", err)
		}
	}
}

func IdentityFromBody(r *http.Request) (IdentityPayload, error) {
	contentType := r.Header.Get(h.HeaderContentType)
	if contentType != vars.JSONType {
		return IdentityPayload{}, fmt.Errorf("invalid content-type: expected %s, got %s", vars.JSONType, contentType)
	}

	var payload IdentityPayload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return IdentityPayload{}, err
	}
	if len(payload.Uid) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty uuid")
	}
	if len(payload.Pwd) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
