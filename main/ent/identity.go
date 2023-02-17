package ent

import "github.com/google/uuid"

type Identity struct {
	Uid        uuid.UUID `gorm:"primaryKey"`
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
	Active     bool
}

type ExternalIdentity struct {
	Uid       uuid.UUID `gorm:"primaryKey"`
	PublicKey []byte
}
