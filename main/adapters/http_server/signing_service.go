package http_server

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

type Operation string

const (
	AnchorHash  Operation = "anchor"
	ChainHash   Operation = "chain"
	DisableHash Operation = "disable"
	EnableHash  Operation = "enable"
	DeleteHash  Operation = "delete"
)

type CheckAuth func(ctx context.Context, uid uuid.UUID, auth string) (ok, found bool, err error)
type Sign func(msg HTTPRequest) (resp HTTPResponse)

type SigningService struct {
	CheckAuth
	Sign
}

// HandleSigningRequest unpacks an incoming HTTP request and calls the Sign function with the according parameters.
// The function expects an Operation as parameter. Supported operations are anchoring, chaining, deleting etc.
//
// There are online and offline signing endpoints for several operations, as well as endpoints for direct hash
// injection and JSON data packages for all operations. For that reason, the function is nested in a way that
// it can be passed to the AddServiceEndpoint function with the following signature:
// func (srv *HTTPServer) AddServiceEndpoint(endpointPath string, handle func(offline bool, isHash bool) http.HandlerFunc, supportOffline bool)
// That way we can call AddServiceEndpoint once for each operation in order to initialize the above endpoints.
func (s *SigningService) HandleSigningRequest(op Operation) func(bool, bool) http.HandlerFunc {
	return func(offline, isHashRequest bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var err error

			msg := HTTPRequest{
				Ctx:       r.Context(),
				Operation: op,
				Offline:   offline,
			}

			msg.ID, err = GetUUID(r)
			if err != nil {
				ClientError(msg.ID, r, w, err.Error(), http.StatusNotFound)
				return
			}

			msg.Auth = AuthToken(r.Header)

			ok, found, err := s.CheckAuth(msg.Ctx, msg.ID, msg.Auth)
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

			msg.Hash, err = GetHash(r, isHashRequest)
			if err != nil {
				ClientError(msg.ID, r, w, err.Error(), http.StatusBadRequest)
				return
			}

			resp := s.Sign(msg)

			select {
			case <-msg.Ctx.Done():
				log.Warnf("%s: signing response could not be sent: http request %s", msg.ID, msg.Ctx.Err())
			default:
				SendResponse(w, resp)
			}
		}
	}
}
