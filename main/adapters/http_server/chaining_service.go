package http_server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type ChainingService struct {
	CheckAuth func(context.Context, uuid.UUID, string) (bool, bool, error)
	Chain     func(HTTPRequest, context.Context) HTTPResponse
}

// Ensure ChainingService implements the Service interface
var _ Service = (*ChainingService)(nil)

func (s *ChainingService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = GetUUID(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth = AuthToken(r.Header)

	ok, found, err := s.CheckAuth(r.Context(), msg.ID, msg.Auth)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !found {
		Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	if !ok {
		Error(msg.ID, w, fmt.Errorf("invalid auth token"), http.StatusUnauthorized)
		return
	}

	msg.Hash, err = GetHash(r)
	if err != nil {
		Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Chain(msg, r.Context())
	SendResponse(w, resp)
}
