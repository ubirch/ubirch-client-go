-- name: StoreIdentity :exec
INSERT INTO identity (uid, private_key, public_key, signature, auth_token)
VALUES ($1, $2, $3, $4, $5);

-- name: LoadIdentity :one
SELECT uid, private_key, public_key, signature, auth_token
FROM identity
WHERE uid = $1;

-- name: StoreActiveFlag :exec
UPDATE identity
SET active = $1
WHERE uid = $2;

-- name: LoadActiveFlagForUpdate :one
SELECT active
FROM identity
WHERE uid = $1 FOR UPDATE;

-- name: LoadActiveFlag :one
SELECT active
FROM identity
WHERE uid = $1;

-- name: StoreSignature :exec
UPDATE identity
SET signature = $1
WHERE uid = $2;

-- name: LoadSignatureForUpdate :one
SELECT signature
FROM identity
WHERE uid = $1 FOR UPDATE;

-- name: StoreAuth :exec
UPDATE identity
SET auth_token = $1
WHERE uid = $2;

-- name: LoadAuthForUpdate :one
SELECT auth_token
FROM identity
WHERE uid = $1 FOR UPDATE;

-- name: StoreExternalIdentity :exec
INSERT INTO external_identity (uid, public_key)
VALUES ($1, $2);

-- name: LoadExternalIdentity :one
SELECT uid, public_key
FROM external_identity
WHERE uid = $1;

-- name: GetIdentityUUIDs :many
SELECT uid
FROM identity;

-- name: GetExternalIdentityUUIDs :many
SELECT uid
FROM external_identity;
