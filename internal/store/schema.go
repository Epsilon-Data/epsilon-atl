package store

const schema = `
CREATE TABLE IF NOT EXISTS atl_entries (
    leaf_index   BIGSERIAL PRIMARY KEY,
    entry_type   SMALLINT NOT NULL,
    entry_cbor   BYTEA NOT NULL,
    leaf_hash    BYTEA NOT NULL UNIQUE,
    job_id       TEXT,
    tee_platform TEXT,
    submitter_id TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tree_heads (
    id         BIGSERIAL PRIMARY KEY,
    tree_size  BIGINT NOT NULL,
    root_hash  BYTEA NOT NULL,
    timestamp  BIGINT NOT NULL,
    signature  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tree_state (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    tree_size       BIGINT NOT NULL,
    compact_hashes  BYTEA NOT NULL,
    internal_nodes  BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
