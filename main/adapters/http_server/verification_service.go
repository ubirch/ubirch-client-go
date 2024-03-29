package http_server

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type Verify func(ctx context.Context, hash []byte) HTTPResponse
type VerifyOffline func(upp []byte, hash []byte) HTTPResponse

type VerificationService struct {
	Verify
	VerifyOffline
}

// HandleVerificationRequest unpacks an incoming HTTP request and calls either Verify or VerifyOffline depending
// on the endpoint the request was received at.
//
// There are online and offline verification endpoints, as well as endpoints for direct hash injection and JSON
// data packages. For that reason, the function is nested in a way that it can be passed to the AddServiceEndpoint
// function with the following signature:
// func (srv *HTTPServer) AddServiceEndpoint(endpointPath string, handle func(offline bool, isHash bool) http.HandlerFunc, supportOffline bool)
func (s *VerificationService) HandleVerificationRequest(offline, isHashRequest bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var resp HTTPResponse

		if offline {

			upp, hash, err := unpackOfflineVerificationRequest(r, isHashRequest)
			if err != nil {
				ClientError(uuid.Nil, r, w, err.Error(), http.StatusBadRequest)
				return
			}

			resp = s.VerifyOffline(upp, hash[:])

		} else {

			hash, err := GetHash(r, isHashRequest)
			if err != nil {
				ClientError(uuid.Nil, r, w, err.Error(), http.StatusBadRequest)
				return
			}

			resp = s.Verify(ctx, hash[:])
		}

		select {
		case <-ctx.Done():
			log.Warnf("verification response could not be sent: http request %s", ctx.Err())
		default:
			SendResponse(w, resp)
		}
	}
}

func unpackOfflineVerificationRequest(r *http.Request, isHashRequest bool) (upp []byte, hash Sha256Sum, err error) {
	upp, err = getUPP(r.Header)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	hash, err = GetHash(r, isHashRequest)
	if err != nil {
		return nil, Sha256Sum{}, err
	}

	return upp, hash, nil
}
