-- Milestone 1 node-isolation hardening.
-- A node parent must belong to the same Space, and active sibling names must
-- be unique even at the root where PostgreSQL NULL semantics would otherwise
-- permit duplicate names.

BEGIN;

ALTER TABLE nodes
    DROP CONSTRAINT nodes_space_id_parent_id_name_key;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_id_space_unique UNIQUE (id, space_id);

ALTER TABLE nodes
    ADD CONSTRAINT nodes_parent_same_space_fk
    FOREIGN KEY (parent_id, space_id)
    REFERENCES nodes (id, space_id)
    ON DELETE RESTRICT;

CREATE UNIQUE INDEX nodes_active_root_name_unique
    ON nodes (space_id, name)
    WHERE parent_id IS NULL AND trashed_at IS NULL;

CREATE UNIQUE INDEX nodes_active_child_name_unique
    ON nodes (space_id, parent_id, name)
    WHERE parent_id IS NOT NULL AND trashed_at IS NULL;

COMMIT;
