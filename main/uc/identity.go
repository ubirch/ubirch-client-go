package uc

import (
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/handlers"
)

func NewIdentityStorer(ctxMng handlers.ContextManager, idHandler *handlers.IdentityHandler) func(ctx context.Context, uid uuid.UUID) error {
	return func(ctx context.Context, uid uuid.UUID) error {

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
			AuthToken: "dsd",
		}

		return ctxMng.StoreIdentity(ctx, identity, idHandler)
	}
}

func NewIdentityFetcher(ctxMng handlers.ContextManager) func(ctx context.Context, uid uuid.UUID) (*ent.Identity, error) {
	return func(ctx context.Context, uid uuid.UUID) (*ent.Identity, error) {
		return ctxMng.FetchIdentity(ctx, uid)
	}
}
