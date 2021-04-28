package uc

import (
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/handlers"
)

func NewIdentityStorer(ctxMng handlers.ContextManager, idHandler *handlers.IdentityHandler) func(ctx context.Context, uid uuid.UUID, authKey string) error {
	return func(ctx context.Context, uid uuid.UUID, authKey string) error {

		prvKey, err := idHandler.Protocol.GenerateKey()
		if err != nil {
			return err
		}

		pubKey, err := idHandler.Protocol.GetPublicKeyFromPrivateKey(prvKey)
		if err != nil {
			return err
		}

		identity := ent.Identity{
			Uid:        uid.String(),
			PrivateKey: prvKey,
			PublicKey:  pubKey,
			AuthToken:  authKey,
		}

		return ctxMng.StoreIdentity(ctx, identity, idHandler)
	}
}

func NewIdentityFetcher(ctxMng handlers.ContextManager) func(uid uuid.UUID) (*ent.Identity, error) {
	return func(uid uuid.UUID) (*ent.Identity, error) {
		return ctxMng.FetchIdentity(uid)
	}
}
