// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0

package postgres

import (
	"github.com/google/uuid"
)

type ExternalIdentity struct {
	Uid       uuid.UUID
	PublicKey []byte
}

type Identity struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
	Active     bool
}
