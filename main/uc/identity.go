package uc

import (
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-client-go/main/todo"
)

func NewIdentityStorer(ctxMng todo.ContextManager) func(ctx context.Context, uid uuid.UUID) error {
	return func(ctx context.Context, uid uuid.UUID) error {

		prvKey, err := ctxMng.GetPrivateKey(uid)
		if err != nil {
			return err
		}

		pubKey, err := ctxMng.GetPublicKey(uid)
		if err != nil {
			return err
		}

		identity := ent.Identity{
			Uid:        uid,
			PrivateKey: prvKey,
			PublicKey:  pubKey,
		}

		return ctxMng.StoreIdentity(ctx, identity)
	}
}

func NewIdentityFetcher(ctxMng todo.ContextManager) func(ctx context.Context, uid uuid.UUID) (*ent.Identity, error) {
	return func(ctx context.Context, uid uuid.UUID) (*ent.Identity, error) {
		return ctxMng.FetchIdentity(ctx, uid)
	}
}
