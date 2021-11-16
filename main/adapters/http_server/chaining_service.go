package http_server

import (
	"context"
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
		ClientError(msg.ID, r, w, err.Error(), http.StatusNotFound)
		return
	}

	ctx := r.Context()
	msg.Auth = AuthToken(r.Header)

	ok, found, err := s.CheckAuth(ctx, msg.ID, msg.Auth)
	if err != nil {
		ServerError(msg.ID, r, w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !found {
		ClientError(msg.ID, r, w, "unknown UUID", http.StatusNotFound)
		return
	}

	if !ok {
		ClientError(msg.ID, r, w, "invalid auth token", http.StatusUnauthorized)
		return
	}

	msg.Hash, err = GetHash(r)
	if err != nil {
		ClientError(msg.ID, r, w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := s.Chain(msg, ctx)

	select {
	case <-ctx.Done():
		log.Warnf("chaining response could not be sent: http request %s", ctx.Err())
	default:
		SendResponse(w, resp)
	}
}
