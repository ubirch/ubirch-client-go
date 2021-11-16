package http_server

import (
	"net/http"

	"github.com/google/uuid"
)

type VerificationService struct {
	Verify func([]byte) HTTPResponse
}

var _ Service = (*VerificationService)(nil)

func (v *VerificationService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := GetHash(r)
	if err != nil {
		ClientError(uuid.Nil, r, w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := v.Verify(hash[:])
	SendResponse(w, resp)
}
