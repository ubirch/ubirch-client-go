package handlers

import (
	"context"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

type FetchIdentity func(ctx context.Context, uid uuid.UUID) (*ent.Identity, error)

type StoreIdentity func(ctx context.Context, uid uuid.UUID, authKey string) error
