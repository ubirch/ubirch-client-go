CREATE TABLE IF NOT EXISTS "protocol_state" (
    "id"   bigint NOT NULL,
    "json" jsonb  NOT NULL,
    PRIMARY KEY ("uuid")
);

CREATE TABLE IF NOT EXISTS "auth" (
    "uuid"       text NOT NULL,
    "key"        text NOT NULL,
    "auth_token" text NOT NULL,
    PRIMARY KEY ("uuid")
);