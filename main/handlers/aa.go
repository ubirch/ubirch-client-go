package handlers

import (
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

type FetchIdentity func(uid uuid.UUID) (*ent.Identity, error)

type StoreIdentity func(uid uuid.UUID, auth string) error

type CheckIdentityExists func(uid uuid.UUID) (bool, error)
