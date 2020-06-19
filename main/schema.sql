CREATE TABLE IF NOT EXISTS "protocol_context" (
    "id"   bigint NOT NULL,
    "json" jsonb  NOT NULL,
    PRIMARY KEY ("id")
);