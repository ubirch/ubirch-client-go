package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
)

type CheckAuth func(uuid.UUID, string) (bool, bool, error)
type Chain func(h.HTTPRequest, context.Context) h.HTTPResponse
type Sign func(h.HTTPRequest, operation) h.HTTPResponse

type ChainingService struct {
	CheckAuth
	Chain
}

// Ensure ChainingService implements the Service interface
var _ h.Service = (*ChainingService)(nil)

func (s *ChainingService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg h.HTTPRequest
	var err error

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth = h.AuthToken(r.Header)

	ok, found, err := s.CheckAuth(msg.ID, msg.Auth)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !found {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	if !ok {
		h.Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Hash, err = h.GetHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Chain(msg, r.Context())
	h.SendResponse(w, resp)
}

type SigningService struct {
	CheckAuth
	Sign
}

var _ h.Service = (*SigningService)(nil)

func (s *SigningService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var msg h.HTTPRequest
	var err error

	msg.ID, err = h.GetUUID(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Auth = h.AuthToken(r.Header)

	ok, found, err := s.CheckAuth(msg.ID, msg.Auth)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !found {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	if !ok {
		h.Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	op, err := getOperation(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = h.GetHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}

	resp := s.Sign(msg, op)
	h.SendResponse(w, resp)
}

type VerificationService struct {
	*Verifier
}

var _ h.Service = (*VerificationService)(nil)

func (v *VerificationService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := h.GetHash(r)
	if err != nil {
		h.Error(uuid.Nil, w, err, http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	h.SendResponse(w, resp)
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, h.OperationKey)
	switch operation(opParam) {
	case anchorHash, disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\" | \"%s\"), got \"%s\"",
			anchorHash, disableHash, enableHash, deleteHash, opParam)
	}
}
