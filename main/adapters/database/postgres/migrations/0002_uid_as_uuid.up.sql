CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

BEGIN;

ALTER TABLE identity
    ALTER uid TYPE uuid USING (uid::uuid);
ALTER TABLE external_identity
    ALTER uid TYPE uuid USING (uid::uuid);

COMMIT;