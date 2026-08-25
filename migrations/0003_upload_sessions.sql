BEGIN;

CREATE TABLE upload_sessions (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    offset_bytes BIGINT NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'completed')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX upload_sessions_owner_lookup_idx ON upload_sessions (account_id, space_id, id);
CREATE INDEX upload_sessions_expiry_idx ON upload_sessions (state, expires_at);

COMMIT;
