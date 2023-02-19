BEGIN;

CREATE TABLE IF NOT EXISTS identity
(
    uid         TEXT    NOT NULL PRIMARY KEY,
    private_key BLOB    NOT NULL,
    public_key  BLOB    NOT NULL,
    signature   BLOB    NOT NULL,
    auth_token  TEXT    NOT NULL,
    active      INTEGER NOT NULL DEFAULT (TRUE)
);

CREATE TABLE IF NOT EXISTS external_identity
(
    uid        TEXT NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL
);

COMMIT;