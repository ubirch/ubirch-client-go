package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
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

func (i Identity) Put(storeId StoreIdentity, fetchId FetchIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := contextFromRequest(r)
		defer cancel()

		authHeader := r.Header.Get(h.XAuthHeader)
		if authHeader != i.globals.Config.AuthToken {
			http.Error(w, fmt.Errorf("not authorized").Error(), http.StatusUnauthorized)
		}

		idPayload, err := IdentityFromBody(r.Body)
		if err != nil {
			h.Respond400(w, err.Error())
			return
		}

		parseUuid, err := uuid.Parse(idPayload.Uid)
		if err != nil {
			h.Respond406(w, err.Error())
			return
		}

		id, err := fetchId(parseUuid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if id != nil {
			h.Respond406(w, fmt.Errorf("uuid already exists in database: %v", id.Uid).Error())
			return
		}

		if err := storeId(ctx, parseUuid, idPayload.Pwd); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
	fmt.Println(payload)
	if len(payload.Pwd) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
