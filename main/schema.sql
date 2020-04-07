

CREATE TABLE IF NOT EXISTS "protocol_context" (
    "id"   bigint NOT NULL,
    "json" jsonb  NOT NULL,
    PRIMARY KEY ("id")
);

-- New
CREATE TABLE IF NOT EXISTS "keystore" (
    "id"   bigint NOT NULL, -- always 1
    "json" jsonb  NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "last_signature" (
    "client_uuid"      text NOT NULL,
    "signature" bytea NOT NULL,
    PRIMARY KEY ("id")
);