CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  api_key TEXT UNIQUE NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  address TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mb_user ON mailboxes(user_id);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  address TEXT NOT NULL,
  from_addr TEXT,
  subject TEXT,
  text TEXT,
  html TEXT,
  code TEXT,
  received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_mb ON messages(mailbox_id, received_at DESC);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
-- v2: webhook, telegram, 2FA, lockout, stars/labels/read, TTL mailboxes, attachments,
-- rules (forward/block/allow), multi-domain, sending, audit log, daily stats, FTS search
ALTER TABLE users ADD COLUMN webhook_url TEXT;
ALTER TABLE users ADD COLUMN webhook_secret TEXT;
ALTER TABLE users ADD COLUMN tg_token TEXT;
ALTER TABLE users ADD COLUMN tg_chat TEXT;
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_on INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN lock_until INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN can_send INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN expires_at INTEGER;
ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN starred INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN labels TEXT NOT NULL DEFAULT '';
ALTER TABLE messages ADD COLUMN att_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  filename TEXT, mime TEXT, size INTEGER, r2_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_att_msg ON attachments(message_id);
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  mailbox_id INTEGER,
  kind TEXT NOT NULL,          -- forward | block | allow
  field TEXT NOT NULL,         -- from | subject | any
  pattern TEXT NOT NULL,
  target TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id);
CREATE TABLE IF NOT EXISTS domains (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
INSERT OR IGNORE INTO domains (name, enabled, created_at) VALUES ('kinoveai.cv', 1, 0);
CREATE TABLE IF NOT EXISTS sent (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL, from_addr TEXT, to_addr TEXT, subject TEXT, status TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sent_user ON sent(user_id, created_at);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT, action TEXT, target TEXT, detail TEXT, ip TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_t ON audit(created_at);
CREATE TABLE IF NOT EXISTS daily_stats (day TEXT PRIMARY KEY, received INTEGER NOT NULL DEFAULT 0, registered INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(subject, from_addr, body, tokenize='trigram');
INSERT INTO messages_fts(rowid, subject, from_addr, body) SELECT id, coalesce(subject,''), coalesce(from_addr,''), substr(coalesce(text,''),1,20000) FROM messages;
