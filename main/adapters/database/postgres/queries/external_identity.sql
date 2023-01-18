-- name: StoreExternalIdentity :exec
INSERT INTO external_identity (uid, public_key)
VALUES ($1, $2);

-- name: LoadExternalIdentity :one
SELECT uid, public_key
FROM external_identity
WHERE uid = $1;

-- name: GetExternalIdentityUUIDs :many
SELECT uid
FROM external_identity;
