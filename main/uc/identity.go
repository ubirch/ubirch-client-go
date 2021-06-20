package uc

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"

	h "github.com/ubirch/ubirch-client-go/lib/httphelper"
)

func NewIdentityStorer(idHandler *handlers.IdentityHandler) h.StoreIdentity {
	return func(uid uuid.UUID, auth string) (csr []byte, err error) {
		return idHandler.InitIdentity(uid, auth)
	}
}

func NewIdentityChecker(idHandler *handlers.IdentityHandler) h.CheckIdentityExists {
	return func(uid uuid.UUID) (bool, error) {
		return idHandler.Protocol.Exists(uid)
	}
}
