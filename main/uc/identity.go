package uc

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/adapters/handlers"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

func NewIdentityStorer(idHandler *handlers.IdentityHandler) handlers.StoreIdentity {
	return func(uid uuid.UUID, auth string) (csr []byte, err error) {
		return idHandler.InitIdentity(uid, auth)
	}
}

func NewIdentityFetcher(idHandler *handlers.IdentityHandler) handlers.FetchIdentity {
	return func(uid uuid.UUID) (*ent.Identity, error) {
		return idHandler.FetchIdentity(uid)
	}
}

func NewIdentityChecker(idHandler *handlers.IdentityHandler) handlers.CheckIdentityExists {
	return func(uid uuid.UUID) (bool, error) {
		return idHandler.Protocol.Exists(uid)
	}
}
