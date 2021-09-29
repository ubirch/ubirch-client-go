package handlers

import (
	"fmt"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/adapters/repository"
	"net/http"
)

type ChainingService struct {
	*Signer
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

	exists, err := s.checkExists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !exists {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	idAuth, err := s.getAuth(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	msg.Auth, err = checkAuth(r, idAuth)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusUnauthorized)
		return
	}

	msg.Hash, err = h.GetHash(r)
	if err != nil {
		h.Error(msg.ID, w, err, http.StatusBadRequest)
		return
	}


	tx, identity, err := s.Protocol.FetchIdentityWithLock(r.Context(), msg.ID, repository.Starting)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	resp := s.chain(msg, tx, identity)
	h.SendResponse(w, resp)
}

type SigningService struct {
	*Signer
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

	exists, err := s.checkExists(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !exists {
		h.Error(msg.ID, w, fmt.Errorf("unknown UUID"), http.StatusNotFound)
		return
	}

	idAuth, err := s.getAuth(msg.ID)
	if err != nil {
		log.Errorf("%s: %v", msg.ID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	msg.Auth, err = checkAuth(r, idAuth)
	if err != nil {
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

// checkAuth compares the auth token from the request header with a given string and returns it if valid
// Returns error if auth token is invalid
func checkAuth(r *http.Request, actualAuth string) (string, error) {
	headerAuthToken := h.AuthToken(r.Header)
	if actualAuth != headerAuthToken {
		return "", fmt.Errorf("invalid auth token")
	}

	return headerAuthToken, nil
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
