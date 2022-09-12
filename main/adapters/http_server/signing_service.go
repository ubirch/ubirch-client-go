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

type SigningService struct {
	CheckAuth func(context.Context, uuid.UUID, string) (bool, bool, error)
	Sign      func(HTTPRequest) HTTPResponse
}

func (s *SigningService) HandleRequest(op Operation) func(bool, bool) http.HandlerFunc {
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
