\set ON_ERROR_STOP on

BEGIN;

INSERT INTO accounts (id, identity_subject, display_name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'test:alice', 'Alice'),
    ('22222222-2222-2222-2222-222222222222', 'test:bob', 'Bob');

INSERT INTO spaces (id, name, kind, owner_account_id) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Alice Personal', 'personal', '11111111-1111-1111-1111-111111111111'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Bob Personal', 'personal', '22222222-2222-2222-2222-222222222222');

INSERT INTO space_memberships (space_id, account_id, role) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'owner'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '22222222-2222-2222-2222-222222222222', 'owner');

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM space_memberships
        WHERE space_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
          AND account_id = '22222222-2222-2222-2222-222222222222'
    ) THEN
        RAISE EXCEPTION 'Bob unexpectedly has membership in Alice personal Space';
    END IF;
END
$$;

INSERT INTO nodes (id, space_id, parent_id, kind, name, created_by) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', NULL, 'folder', 'Documents', '11111111-1111-1111-1111-111111111111');

DO $$
BEGIN
    BEGIN
        INSERT INTO nodes (id, space_id, parent_id, kind, name, created_by) VALUES
            ('bbbbbbbb-0000-0000-0000-000000000001', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'aaaaaaaa-0000-0000-0000-000000000001', 'file', 'cross-space.txt', '22222222-2222-2222-2222-222222222222');
        RAISE EXCEPTION 'cross-Space parent relationship was accepted';
    EXCEPTION
        WHEN foreign_key_violation THEN NULL;
    END;
END
$$;

DO $$
BEGIN
    BEGIN
        INSERT INTO nodes (id, space_id, parent_id, kind, name, created_by) VALUES
            ('aaaaaaaa-0000-0000-0000-000000000002', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', NULL, 'folder', 'Documents', '11111111-1111-1111-1111-111111111111');
        RAISE EXCEPTION 'duplicate active root name was accepted';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;
END
$$;

UPDATE nodes
SET trashed_at = now()
WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001';

INSERT INTO nodes (id, space_id, parent_id, kind, name, created_by) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000003', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', NULL, 'folder', 'Documents', '11111111-1111-1111-1111-111111111111');

ROLLBACK;
