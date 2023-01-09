CREATE TABLE identity
(
    uid         VARCHAR(255) NOT NULL PRIMARY KEY,
    private_key BYTEA        NOT NULL,
    public_key  BYTEA        NOT NULL,
    signature   BYTEA        NOT NULL,
    auth_token  VARCHAR(255) NOT NULL,
    active      boolean      NOT NULL DEFAULT (TRUE)
);

CREATE TABLE external_identity
(
    uid        VARCHAR(255) NOT NULL PRIMARY KEY,
    public_key BYTEA        NOT NULL
);