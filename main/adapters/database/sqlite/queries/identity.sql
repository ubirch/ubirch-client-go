-- name: StoreIdentity :exec
INSERT INTO identity (uid, private_key, public_key, signature, auth_token, active)
VALUES (?, ?, ?, ?, ?, ?);

-- name: LoadIdentity :one
SELECT uid, private_key, public_key, signature, auth_token, active
FROM identity
WHERE uid = ?;

-- name: StoreActiveFlag :exec
UPDATE identity
SET active = ?
WHERE uid = ?;

-- name: LoadActiveFlagForUpdate :one
SELECT active
FROM identity
WHERE uid = ?;

-- name: LoadActiveFlag :one
SELECT active
FROM identity
WHERE uid = ?;

-- name: StoreSignature :exec
UPDATE identity
SET signature = ?
WHERE uid = ?;

-- name: LoadSignatureForUpdate :one
SELECT signature
FROM identity
WHERE uid = ?;

-- name: StoreAuth :exec
UPDATE identity
SET auth_token = ?
WHERE uid = ?;

-- name: LoadAuthForUpdate :one
SELECT auth_token
FROM identity
WHERE uid = ?;

-- name: GetIdentityUUIDs :many
SELECT uid
FROM identity;
