-- Auth Datamodel: indexes. Run after the columns of every table are known to exist.
-- Rows with an empty value (a column that was added to an existing table) are left out of the
-- unique indexes, so several of them can wait for real values.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token) WHERE refresh_token <> '';
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
