-- name: StoreExternalIdentity :exec
INSERT INTO external_identity (uid, public_key)
VALUES (?, ?);

-- name: LoadExternalIdentity :one
SELECT uid, public_key
FROM external_identity
WHERE uid = ?;

-- name: GetExternalIdentityUUIDs :many
SELECT uid
FROM external_identity;
