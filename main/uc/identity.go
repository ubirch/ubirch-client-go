package uc

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
)

func NewIdentityStorer(idHandler *handlers.IdentityHandler) handlers.StoreIdentity {
	return func(uid uuid.UUID, auth string) (csr []byte, err error) {
		return idHandler.InitIdentity(uid, auth)
	}
}

func NewIdentityChecker(idHandler *handlers.IdentityHandler) handlers.CheckIdentityExists {
	return func(uid uuid.UUID) (bool, error) {
		return idHandler.Protocol.Exists(uid)
	}
}
