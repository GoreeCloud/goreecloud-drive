-- Preserve the authorized file node independently from its parent and display name.
BEGIN;

ALTER TABLE upload_sessions
    ADD COLUMN node_id uuid REFERENCES nodes(id) ON DELETE RESTRICT;

CREATE INDEX upload_sessions_node_idx ON upload_sessions (node_id);

COMMIT;
