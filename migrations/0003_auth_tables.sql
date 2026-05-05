-- migrations/0003_auth_tables.sql
-- Full auth schema: users, sessions, refresh tokens, email verifications,
-- password resets, roles, audit log

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              TEXT    PRIMARY KEY,          -- UUID
  email           TEXT    NOT NULL UNIQUE,
  password_hash   TEXT    NOT NULL,             -- bcrypt-style PBKDF2 hash
  name            TEXT    NOT NULL DEFAULT '',
  role            TEXT    NOT NULL DEFAULT 'viewer',  -- 'admin' | 'editor' | 'viewer'
  email_verified  INTEGER NOT NULL DEFAULT 0,
  is_active       INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT    NOT NULL,             -- ISO timestamp
  updated_at      TEXT    NOT NULL
);

-- ── Sessions (JWT access-token metadata) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT    PRIMARY KEY,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  ip_address  TEXT    DEFAULT '',
  user_agent  TEXT    DEFAULT ''
);

-- ── Refresh tokens ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          TEXT    PRIMARY KEY,              -- UUID, stored as hash
  token_hash  TEXT    NOT NULL UNIQUE,          -- SHA-256 of the actual token
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id  TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  created_at  TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);

-- ── Email verification tokens ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_verifications (
  id          TEXT    PRIMARY KEY,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  created_at  TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0
);

-- ── Password reset tokens ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
  id          TEXT    PRIMARY KEY,
  user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  created_at  TEXT    NOT NULL,
  expires_at  TEXT    NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0
);

-- ── Audit log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT    REFERENCES users(id),
  action      TEXT    NOT NULL,   -- e.g. 'login', 'booking.create', 'user.role_change'
  target_type TEXT    DEFAULT '', -- e.g. 'booking', 'room', 'user'
  target_id   TEXT    DEFAULT '',
  detail      TEXT    DEFAULT '', -- JSON string of relevant fields
  ip_address  TEXT    DEFAULT '',
  created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_user       ON refresh_tokens(user_id);
