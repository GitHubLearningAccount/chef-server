-- Revert orgs table

BEGIN;

DROP TABLE IF EXISTS orgs;

COMMIT;
