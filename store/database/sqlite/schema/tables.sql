-- Auth Datamodel: tables. Run only after checking existing tables, see migrate.go.
-- Keep the column lists in sync with the tables variable in migrate.go.
-- Uniqueness lives in indexes.sql so a table that already exists gets the same rules as a new one.
CREATE TABLE IF NOT EXISTS users (
    user_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    pwd_hash   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    refresh_token TEXT NOT NULL DEFAULT '',
    valid_until   TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS path_permissions (
    user_id    INTEGER NOT NULL,
    path       TEXT NOT NULL,
    PRIMARY KEY (user_id, path),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ops_permissions (
    user_id    INTEGER NOT NULL,
    operation  TEXT NOT NULL,
    PRIMARY KEY (user_id, operation),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    event      TEXT NOT NULL,
    user_id    INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit (
    audit_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    event      TEXT NOT NULL,
    user_id    INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);
