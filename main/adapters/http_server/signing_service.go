package http_server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Operation string

const (
	AnchorHash  Operation = "anchor"
	DisableHash Operation = "disable"
	EnableHash  Operation = "enable"
	DeleteHash  Operation = "delete"
)

type SigningService struct {
	CheckAuth func(context.Context, uuid.UUID, string) (bool, bool, error)
	Sign      func(HTTPRequest, Operation) HTTPResponse
}

var _ Service = (*SigningService)(nil)

func (s *SigningService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = GetUUID(r)
	if err != nil {
		ClientError(msg.ID, r, w, err.Error(), http.StatusNotFound)
		return
	}

	msg.Auth = AuthToken(r.Header)

	ok, found, err := s.CheckAuth(r.Context(), msg.ID, msg.Auth)
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

	op, err := getOperation(r)
	if err != nil {
		ClientError(msg.ID, r, w, err.Error(), http.StatusNotFound)
		return
	}

	msg.Hash, err = GetHash(r)
	if err != nil {
		ClientError(msg.ID, r, w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := s.Sign(msg, op)
	SendResponse(w, resp)
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (Operation, error) {
	opParam := chi.URLParam(r, OperationKey)
	switch Operation(opParam) {
	case AnchorHash, DisableHash, EnableHash, DeleteHash:
		return Operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			AnchorHash, DisableHash, EnableHash, DeleteHash, opParam)
	}
}
