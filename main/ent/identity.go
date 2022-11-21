package ent

import "github.com/google/uuid"

type Identity struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
}

type ExternalIdentity struct {
	Uid       uuid.UUID
	PublicKey []byte
}
