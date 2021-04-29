package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"io"
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
		}

		idPayload, err := IdentityFromBody(r.Body)
		if err != nil {
			h.Respond400(w, err.Error())
			return
		}

		parseUuid, err := uuid.Parse(idPayload.Uid)
		if err != nil {
			h.Respond400(w, err.Error())
			return
		}

		exists, err := idExists(parseUuid)
		if err != nil {
			Error(parseUuid, w, err, http.StatusInternalServerError)
			return
		}
		if exists {
			Error(parseUuid, w, fmt.Errorf("identity already registered"), http.StatusConflict)
			return
		}

		if err := storeId(parseUuid, idPayload.Pwd); err != nil {
			Error(parseUuid, w, err, http.StatusInternalServerError)
			return
		}

		h.Ok(w, fmt.Sprintf("successfully created new entry with uuid %s", parseUuid.String()))
	}
}

func IdentityFromBody(in io.ReadCloser) (IdentityPayload, error) {
	var payload IdentityPayload
	decoder := json.NewDecoder(in)
	if err := decoder.Decode(&payload); err != nil {
		return IdentityPayload{}, err
	}
	if len(payload.Pwd) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
