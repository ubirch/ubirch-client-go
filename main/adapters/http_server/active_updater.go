package http_server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type ActiveUpdatePayload struct {
	Uid    uuid.UUID `json:"id"`
	Active bool      `json:"active"`
}

func UpdateActive(auth string,
	deactivate func(uid uuid.UUID) error,
	reactivate func(uid uuid.UUID) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if AuthToken(r.Header) != auth {
			log.Warnf("unauthorized key de-/re-activation attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		activeUpdatePayload, err := GetActiveUpdatePayload(r)
		if err != nil {
			log.Warnf("unsuccessful key de-/re-activation attempt: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var action string

		uid := activeUpdatePayload.Uid

		if activeUpdatePayload.Active {
			action = "key reactivation"
			err = reactivate(uid)
		} else {
			action = "key deactivation"
			err = deactivate(uid)
		}
		if err != nil {
			switch err {
			case ErrUnknown:
				ClientError(uid, r, w, err.Error(), http.StatusNotFound)
			case ErrAlreadyActivated, ErrAlreadyDeactivated:
				ClientError(uid, r, w, err.Error(), http.StatusConflict)
			default:
				ServerError(uid, r, w, fmt.Sprint(action, " failed: ", err), http.StatusInternalServerError)
			}
			return
		}

		SendResponse(w, HTTPResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
			Content:    []byte(action + " successful\n"),
		})
	}
}

func GetActiveUpdatePayload(r *http.Request) (*ActiveUpdatePayload, error) {
	contentType := ContentType(r.Header)
	if contentType != JSONType {
		return nil, fmt.Errorf("invalid content-type: expected %s, got %s", JSONType, contentType)
	}

	reqBodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	log.Debugf("%s : %s", r.RequestURI, string(reqBodyBytes))

	payload := &ActiveUpdatePayload{}
	decoder := json.NewDecoder(bytes.NewBuffer(reqBodyBytes))
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Uid == uuid.Nil {
		return nil, fmt.Errorf("empty uuid")
	}
	return payload, nil
}
