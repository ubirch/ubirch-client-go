package http_server

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type Verify func([]byte) HTTPResponse
type VerifyOffline func([]byte, []byte) HTTPResponse

type VerificationService struct {
	Verify
	VerifyOffline
}

func (s *VerificationService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var resp HTTPResponse

	if strings.Contains(r.URL.Path, OfflinePath) {

		upp, hash, err := unpackOfflineVerificationRequest(r)
		if err != nil {
			ClientError(uuid.Nil, r, w, err.Error(), http.StatusBadRequest)
			return
		}

		resp = s.VerifyOffline(upp, hash[:])

	} else {

		hash, err := GetHash(r)
		if err != nil {
			ClientError(uuid.Nil, r, w, err.Error(), http.StatusBadRequest)
			return
		}

		resp = s.Verify(hash[:])
	}

	ctx := r.Context()
	select {
	case <-ctx.Done():
		log.Warnf("verification response could not be sent: http request %s", ctx.Err())
	default:
		SendResponse(w, resp)
	}
}

func unpackOfflineVerificationRequest(r *http.Request) (upp []byte, hash Sha256Sum, err error) {
	upp, err = getUPP(r.Header)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	hash, err = GetHash(r)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	return upp, hash, nil
}
