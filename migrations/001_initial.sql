-- Run only as the local database administrator, never from the application role.
BEGIN;
CREATE TABLE datasets (tenant_id UUID NOT NULL, dataset_id VARCHAR(256) NOT NULL,
    file_sha256 VARCHAR(64) NOT NULL, PRIMARY KEY (tenant_id, dataset_id));
CREATE TABLE events (tenant_id UUID NOT NULL, event_id VARCHAR(36) NOT NULL,
    dataset_id VARCHAR(256) NOT NULL, occurred_at VARCHAR(40) NOT NULL, data JSONB NOT NULL,
    PRIMARY KEY (tenant_id, event_id));
CREATE INDEX events_scope_time ON events(tenant_id, dataset_id, occurred_at, event_id);
CREATE TABLE source_records (tenant_id UUID NOT NULL, dataset_id VARCHAR(256) NOT NULL,
    file_sha256 VARCHAR(64) NOT NULL, row_index INTEGER NOT NULL,
    raw_row_sha256 VARCHAR(64) NOT NULL, event_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (tenant_id, dataset_id, file_sha256, row_index));
CREATE TABLE cases (tenant_id UUID NOT NULL, case_id VARCHAR(36) NOT NULL,
    dataset_id VARCHAR(256) NOT NULL, data JSONB NOT NULL, PRIMARY KEY (tenant_id, case_id));
CREATE TABLE reports (tenant_id UUID NOT NULL, case_id VARCHAR(36) NOT NULL,
    data JSONB NOT NULL, PRIMARY KEY (tenant_id, case_id));
CREATE TABLE audit (tenant_id UUID NOT NULL, audit_id VARCHAR(36) NOT NULL,
    data JSONB NOT NULL, PRIMARY KEY (tenant_id, audit_id));
DO $body$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['datasets','events','source_records','cases','reports','audit'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($policy$CREATE POLICY tenant_scope ON %I USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$policy$, t);
  END LOOP;
END $body$;
COMMIT;
