const path = require("path");

const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();

const DB_PATH = path.join(__dirname, "users.db");
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

async function tableExists(name) {
  const row = await get(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
    [name]
  );
  return !!row;
}

async function tableColumns(name) {
  // Name is hardcoded by our callers; do not pass user input here.
  return all(`PRAGMA table_info(${name})`);
}

async function migrateUsersTableIfNeeded() {
  const exists = await tableExists("users");
  if (!exists) return;

  const cols = await tableColumns("users");
  const names = new Set(cols.map((c) => c.name));
  if (names.has("password_hash") && names.has("bio") && names.has("created_at")) return;

  // Old schema: (id, username, password). We migrate to:
  // (id, username UNIQUE, password_hash, bio, created_at)
  await run(`
    CREATE TABLE IF NOT EXISTS users_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    )
  `);

  const oldRows = await all("SELECT id, username, password FROM users");
  for (const r of oldRows) {
    const username = String(r.username || "").trim();
    const password = String(r.password || "");
    if (!username) continue;
    const hash = await bcrypt.hash(password, 10);
    await run(
      "INSERT OR REPLACE INTO users_new (id, username, password_hash, bio, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
      [r.id, username, hash, ""]
    );
  }

  await run("DROP TABLE users");
  await run("ALTER TABLE users_new RENAME TO users");
}

async function ensureSchema() {
  await migrateUsersTableIfNeeded();

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      flagged INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      message TEXT NOT NULL,
      meta_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    )
  `);
}

async function seedData() {
  const seeds = [
    { username: "admin", password: "admin123", bio: "System administrator (demo account)." },
    { username: "user", password: "password", bio: "Regular user (demo account)." },
    { username: "test", password: "test123", bio: "Test account for learning." },
  ];

  for (const s of seeds) {
    const hash = await bcrypt.hash(s.password, 10);
    await run(
      `
        INSERT OR IGNORE INTO users (username, password_hash, bio, created_at)
        VALUES (?, ?, ?, datetime('now'))
      `,
      [s.username, hash, s.bio]
    );

    // If user already exists (older DB), ensure it has a password_hash.
    await run("UPDATE users SET password_hash = COALESCE(password_hash, ?) WHERE username = ?", [
      hash,
      s.username,
    ]);
  }

  const count = await get("SELECT COUNT(*) AS count FROM comments");
  if ((count?.count ?? 0) === 0) {
    const admin = await get("SELECT id FROM users WHERE username = 'admin'");
    const user = await get("SELECT id FROM users WHERE username = 'user'");

    const rows = [
      { userId: admin?.id || 1, content: "Welcome to VulnLab. Try Demo Mode payloads safely.", flagged: 0 },
      {
        userId: user?.id || 2,
        content: "[[SIM_XSS]] (safe simulation token; rendered as text)",
        flagged: 1,
      },
    ];

    for (const r of rows) {
      await run(
        "INSERT INTO comments (user_id, content, flagged, created_at) VALUES (?, ?, ?, datetime('now'))",
        [r.userId, r.content, r.flagged]
      );
    }
  }
}

async function logEvent(type, message, meta = {}) {
  const metaJson = JSON.stringify(meta ?? {});
  await run(
    "INSERT INTO events (type, message, meta_json, created_at) VALUES (?, ?, ?, datetime('now'))",
    [String(type), String(message), metaJson]
  );
}

async function listEvents({ limit = 40, afterId = 0 } = {}) {
  const lim = Math.max(1, Math.min(200, Number(limit) || 40));
  const after = Math.max(0, Number(afterId) || 0);
  const rows = await all(
    "SELECT id, type, message, meta_json AS metaJson, created_at AS createdAt FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
    [after, lim]
  );
  return rows.map((r) => {
    let meta = {};
    try {
      meta = r.metaJson ? JSON.parse(r.metaJson) : {};
    } catch {
      meta = {};
    }
    return {
      id: r.id,
      type: r.type,
      message: r.message,
      meta,
      createdAt: r.createdAt,
    };
  });
}

async function getAdminStats() {
  const users = await get("SELECT COUNT(*) AS count FROM users");
  const comments = await get("SELECT COUNT(*) AS count FROM comments");
  const events = await get("SELECT COUNT(*) AS count FROM events");
  const sqli = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'sqli_detected'");
  const xss = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'xss_detected'");
  const idor = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'idor_attempt'");
  const login = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'login_attempt'");
  const success = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'login_success'");
  const toolRuns = await get("SELECT COUNT(*) AS count FROM events WHERE type = 'tool_run'");

  return {
    totals: {
      users: users?.count ?? 0,
      comments: comments?.count ?? 0,
      events: events?.count ?? 0,
      loginAttempts: login?.count ?? 0,
      loginSuccess: success?.count ?? 0,
      sqliDetected: sqli?.count ?? 0,
      xssDetected: xss?.count ?? 0,
      idorAttempts: idor?.count ?? 0,
      toolRuns: toolRuns?.count ?? 0,
    },
  };
}

async function init() {
  await ensureSchema();
  await seedData();
}

async function getUserById(id) {
  const row = await get("SELECT id, username, password_hash, bio, created_at FROM users WHERE id = ?", [id]);
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    bio: row.bio || "",
    createdAt: row.created_at,
    isAdmin: row.username === "admin",
  };
}

async function getUserByUsername(username) {
  const row = await get("SELECT id, username, password_hash, bio, created_at FROM users WHERE username = ?", [
    username,
  ]);
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    bio: row.bio || "",
    createdAt: row.created_at,
    isAdmin: row.username === "admin",
    passwordHash: row.password_hash,
  };
}

async function createUser({ username, password }) {
  const hash = await bcrypt.hash(password, 10);
  const res = await run(
    "INSERT INTO users (username, password_hash, bio, created_at) VALUES (?, ?, '', datetime('now'))",
    [username, hash]
  );
  const user = await getUserById(res.lastID);
  return user;
}

async function verifyLogin({ username, password }) {
  const row = await get("SELECT id, username, password_hash, bio, created_at FROM users WHERE username = ?", [
    username,
  ]);
  if (!row) return null;
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return null;
  return {
    id: row.id,
    username: row.username,
    bio: row.bio || "",
    createdAt: row.created_at,
    isAdmin: row.username === "admin",
  };
}

async function updateBio(userId, bio) {
  await run("UPDATE users SET bio = ? WHERE id = ?", [bio, userId]);
}

async function addComment({ userId, content, flagged }) {
  await run("INSERT INTO comments (user_id, content, flagged, created_at) VALUES (?, ?, ?, datetime('now'))", [
    userId,
    content,
    flagged ? 1 : 0,
  ]);
}

async function listComments() {
  const rows = await all(
    `
      SELECT c.id, c.content, c.flagged, c.created_at AS createdAt, u.username
      FROM comments c
      JOIN users u ON u.id = c.user_id
      ORDER BY c.id DESC
      LIMIT 50
    `
  );
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    content: String(r.content || ""),
    flagged: !!r.flagged,
    createdAt: r.createdAt,
  }));
}

async function searchUsersByUsername(term) {
  const t = String(term || "");
  const rows = await all("SELECT id, username FROM users WHERE username LIKE ? ORDER BY username LIMIT 20", [
    `%${t}%`,
  ]);
  return rows.map((r) => ({ id: r.id, username: r.username }));
}

async function listUsersAdminSafe() {
  const rows = await all("SELECT id, username, password_hash FROM users ORDER BY id");
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    isAdmin: r.username === "admin",
    passwordHash: r.password_hash,
  }));
}

module.exports = {
  db,
  init,
  getUserById,
  getUserByUsername,
  createUser,
  verifyLogin,
  updateBio,
  addComment,
  listComments,
  searchUsersByUsername,
  listUsersAdminSafe,
  logEvent,
  listEvents,
  getAdminStats,
};
