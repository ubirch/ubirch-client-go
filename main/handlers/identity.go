package handlers

import (
	"encoding/json"
	"github.com/google/uuid"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"io"
	"net/http"
)

type Identity struct {
	globals Globals
}

type IdentityPayload struct {
	uid uuid.UUID `json:"organisation"`
	pwd string    `json:"password"`
}

func NewIdentity(globals Globals) Identity {
	return Identity{globals: globals}
}

func (i Identity) Put(storeId StoreIdentity, fetchId FetchIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := contextFromRequest(r)
		defer cancel()

		//TODO: Create a correct auth handler
		r.Header.Get(h.XAuthHeader)

		idPayload, err := IdentityFromBody(r.Body)
		if err != nil {
			h.Respond400(w, err.Error())
			return
		}

		if _, err = fetchId(ctx, idPayload.uid); err == nil {
			h.Respond409(w, err.Error())
			return
		}

		if err := storeId(ctx, idPayload.uid); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.EmptyOk(w)
	}
}

func IdentityFromBody(in io.ReadCloser) (IdentityPayload, error) {
	var payload IdentityPayload
	decoder := json.NewDecoder(in)
	if err := decoder.Decode(&payload); err != nil {
		return IdentityPayload{}, err
	}
	return payload, nil
}

