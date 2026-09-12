-- Auth Datamodel
CREATE TABLE IF NOT EXISTS users (
    user_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    email      TEXT NOT NULL UNIQUE,
    pwd_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    user_id       INTEGER NOT NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    valid_until   TEXT NOT NULL,
    PRIMARY KEY (user_id),
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


-- Debugging table 
CREATE TABLE IF NOT EXISTS events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    event      TEXT NOT NULL,
    user_id    INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Audit table 
CREATE TABLE IF NOT EXISTS audit (
    audit_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    event      TEXT NOT NULL,
    user_id    INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);
