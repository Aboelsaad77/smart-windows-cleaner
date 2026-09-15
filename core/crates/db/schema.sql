-- Smart Cleaner local database schema (spec §21).
-- Everything is local; nothing in this database is ever transmitted.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    INTEGER NOT NULL,
    mode          TEXT NOT NULL,          -- quick | smart | deep
    finished_at   INTEGER,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    total_size    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id           INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    path                 TEXT NOT NULL,
    size                 INTEGER NOT NULL,
    modified             INTEGER NOT NULL,
    file_class           TEXT NOT NULL,
    content_kind         TEXT,
    extension            TEXT,
    sha256               TEXT,
    owner_app            TEXT,
    is_windows_component INTEGER NOT NULL DEFAULT 0,
    in_use               INTEGER NOT NULL DEFAULT 0,
    last_scanned         INTEGER NOT NULL,
    UNIQUE (session_id, path)
);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size DESC);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT NOT NULL,
    session_id INTEGER,
    score      INTEGER NOT NULL,
    band       TEXT NOT NULL,
    factors    TEXT NOT NULL,             -- JSON array of {rule, delta}
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id             TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    vault_path     TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    quarantined_at INTEGER NOT NULL,
    reason         TEXT,
    risk_score     INTEGER,
    status         TEXT NOT NULL          -- quarantined | restored | purged
);

CREATE TABLE IF NOT EXISTS cleanup_operations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    action     TEXT NOT NULL,             -- quarantine | restore | purge
    path       TEXT NOT NULL,
    size       INTEGER,
    risk       TEXT,
    reason     TEXT,
    engine     TEXT NOT NULL,             -- local-rules | ai-second-opinion
    result     TEXT NOT NULL              -- success | error
);

CREATE TABLE IF NOT EXISTS user_exclusions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT NOT NULL UNIQUE,
    scope      TEXT NOT NULL,             -- file | folder | app
    created_at INTEGER NOT NULL,
    note       TEXT
);

CREATE TABLE IF NOT EXISTS software (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL UNIQUE,
    publisher      TEXT,
    install_location TEXT,
    version        TEXT,
    installed_at   INTEGER
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT NOT NULL,
    request_json  TEXT NOT NULL,
    response_json TEXT,
    source        TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    action     TEXT NOT NULL,
    path       TEXT,
    size       INTEGER,
    risk       TEXT,
    reason     TEXT,
    engine     TEXT,
    result     TEXT NOT NULL,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
