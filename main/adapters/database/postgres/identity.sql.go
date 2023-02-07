// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0
// source: identity.sql

package postgres

import (
	"context"

	"github.com/google/uuid"
)

const getIdentityUUIDs = `-- name: GetIdentityUUIDs :many
SELECT uid
FROM identity
`

func (q *Queries) GetIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := q.db.QueryContext(ctx, getIdentityUUIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []uuid.UUID
	for rows.Next() {
		var uid uuid.UUID
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		items = append(items, uid)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const loadActiveFlag = `-- name: LoadActiveFlag :one
SELECT active
FROM identity
WHERE uid = $1
`

func (q *Queries) LoadActiveFlag(ctx context.Context, uid uuid.UUID) (bool, error) {
	row := q.db.QueryRowContext(ctx, loadActiveFlag, uid)
	var active bool
	err := row.Scan(&active)
	return active, err
}

const loadActiveFlagForUpdate = `-- name: LoadActiveFlagForUpdate :one
SELECT active
FROM identity
WHERE uid = $1 FOR UPDATE
`

func (q *Queries) LoadActiveFlagForUpdate(ctx context.Context, uid uuid.UUID) (bool, error) {
	row := q.db.QueryRowContext(ctx, loadActiveFlagForUpdate, uid)
	var active bool
	err := row.Scan(&active)
	return active, err
}

const loadAuthForUpdate = `-- name: LoadAuthForUpdate :one
SELECT auth_token
FROM identity
WHERE uid = $1 FOR UPDATE
`

func (q *Queries) LoadAuthForUpdate(ctx context.Context, uid uuid.UUID) (string, error) {
	row := q.db.QueryRowContext(ctx, loadAuthForUpdate, uid)
	var auth_token string
	err := row.Scan(&auth_token)
	return auth_token, err
}

const loadIdentity = `-- name: LoadIdentity :one
SELECT uid, private_key, public_key, signature, auth_token, active
FROM identity
WHERE uid = $1
`

func (q *Queries) LoadIdentity(ctx context.Context, uid uuid.UUID) (Identity, error) {
	row := q.db.QueryRowContext(ctx, loadIdentity, uid)
	var i Identity
	err := row.Scan(
		&i.Uid,
		&i.PrivateKey,
		&i.PublicKey,
		&i.Signature,
		&i.AuthToken,
		&i.Active,
	)
	return i, err
}

const loadSignatureForUpdate = `-- name: LoadSignatureForUpdate :one
SELECT signature
FROM identity
WHERE uid = $1 FOR UPDATE
`

func (q *Queries) LoadSignatureForUpdate(ctx context.Context, uid uuid.UUID) ([]byte, error) {
	row := q.db.QueryRowContext(ctx, loadSignatureForUpdate, uid)
	var signature []byte
	err := row.Scan(&signature)
	return signature, err
}

const storeActiveFlag = `-- name: StoreActiveFlag :exec
UPDATE identity
SET active = $1
WHERE uid = $2
`

type StoreActiveFlagParams struct {
	Active bool
	Uid    uuid.UUID
}

func (q *Queries) StoreActiveFlag(ctx context.Context, arg StoreActiveFlagParams) error {
	_, err := q.db.ExecContext(ctx, storeActiveFlag, arg.Active, arg.Uid)
	return err
}

const storeAuth = `-- name: StoreAuth :exec
UPDATE identity
SET auth_token = $1
WHERE uid = $2
`

type StoreAuthParams struct {
	AuthToken string
	Uid       uuid.UUID
}

func (q *Queries) StoreAuth(ctx context.Context, arg StoreAuthParams) error {
	_, err := q.db.ExecContext(ctx, storeAuth, arg.AuthToken, arg.Uid)
	return err
}

const storeIdentity = `-- name: StoreIdentity :exec
INSERT INTO identity (uid, private_key, public_key, signature, auth_token, active)
VALUES ($1, $2, $3, $4, $5, $6)
`

type StoreIdentityParams struct {
	Uid        uuid.UUID
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
	Active     bool
}

func (q *Queries) StoreIdentity(ctx context.Context, arg StoreIdentityParams) error {
	_, err := q.db.ExecContext(ctx, storeIdentity,
		arg.Uid,
		arg.PrivateKey,
		arg.PublicKey,
		arg.Signature,
		arg.AuthToken,
		arg.Active,
	)
	return err
}

const storeSignature = `-- name: StoreSignature :exec
UPDATE identity
SET signature = $1
WHERE uid = $2
`

type StoreSignatureParams struct {
	Signature []byte
	Uid       uuid.UUID
}

func (q *Queries) StoreSignature(ctx context.Context, arg StoreSignatureParams) error {
	_, err := q.db.ExecContext(ctx, storeSignature, arg.Signature, arg.Uid)
	return err
}
