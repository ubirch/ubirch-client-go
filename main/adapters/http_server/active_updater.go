package http_server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type ActiveUpdatePayload struct {
	Uid    uuid.UUID `json:"id"`
	Active bool      `json:"active"`
}

func UpdateActive(auth string,
	deactivate func(uid uuid.UUID) HTTPResponse,
	reactivate func(uid uuid.UUID) HTTPResponse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if AuthToken(r.Header) != auth {
			log.Warnf("unauthorized key deactivation/reactivation attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		activeUpdatePayload, err := GetActiveUpdatePayload(r)
		if err != nil {
			log.Warnf("unsuccessful key deactivation/reactivation attempt: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := HTTPResponse{}

		if activeUpdatePayload.Active {
			resp = reactivate(activeUpdatePayload.Uid)
		} else {
			resp = deactivate(activeUpdatePayload.Uid)
		}

		SendResponse(w, resp)
	}
}

func GetActiveUpdatePayload(r *http.Request) (*ActiveUpdatePayload, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return nil, fmt.Errorf("invalid content-type: expected %s, got %s", JSONType, contentType)
	}

	payload := &ActiveUpdatePayload{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Uid == uuid.Nil {
		return nil, fmt.Errorf("empty uuid")
	}
	return payload, nil
}
