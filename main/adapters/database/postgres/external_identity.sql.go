// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0
// source: external_identity.sql

package postgres

import (
	"context"

	"github.com/google/uuid"
)

const getExternalIdentityUUIDs = `-- name: GetExternalIdentityUUIDs :many
SELECT uid
FROM external_identity
`

func (q *Queries) GetExternalIdentityUUIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := q.db.QueryContext(ctx, getExternalIdentityUUIDs)
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

const loadExternalIdentity = `-- name: LoadExternalIdentity :one
SELECT uid, public_key
FROM external_identity
WHERE uid = $1
`

func (q *Queries) LoadExternalIdentity(ctx context.Context, uid uuid.UUID) (ExternalIdentity, error) {
	row := q.db.QueryRowContext(ctx, loadExternalIdentity, uid)
	var i ExternalIdentity
	err := row.Scan(&i.Uid, &i.PublicKey)
	return i, err
}

const storeExternalIdentity = `-- name: StoreExternalIdentity :exec
INSERT INTO external_identity (uid, public_key)
VALUES ($1, $2)
`

type StoreExternalIdentityParams struct {
	Uid       uuid.UUID
	PublicKey []byte
}

func (q *Queries) StoreExternalIdentity(ctx context.Context, arg StoreExternalIdentityParams) error {
	_, err := q.db.ExecContext(ctx, storeExternalIdentity, arg.Uid, arg.PublicKey)
	return err
}
