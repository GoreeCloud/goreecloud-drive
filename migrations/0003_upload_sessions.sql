BEGIN;

ALTER TABLE upload_sessions
    ADD COLUMN node_id uuid REFERENCES nodes(id) ON DELETE CASCADE;

CREATE INDEX upload_sessions_space_lookup_idx
    ON upload_sessions (account_id, space_id, id);

CREATE INDEX upload_sessions_expiry_idx
    ON upload_sessions (state, expires_at);

COMMIT;
