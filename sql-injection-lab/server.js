const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const cookieParser = require("cookie-parser");
const express = require("express");

const db = require("./database");

const PORT = 3000;

const app = express();
app.set("trust proxy", false);

function nowMs() {
  return Date.now();
}

function randomId(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

function isLocalRequest(req) {
  const addr = req.socket?.remoteAddress || "";
  return (
    addr === "127.0.0.1" ||
    addr === "::1" ||
    addr === "::ffff:127.0.0.1" ||
    addr === "0:0:0:0:0:0:0:1"
  );
}

function normalizeMode(value) {
  return value === "secure" ? "secure" : "demo";
}

function looksLikeSqlInjection(input) {
  const s = String(input || "").toLowerCase();
  if (s.includes("[[sim_sqli]]")) return true;
  const patterns = [
    /--/,
    /\/\*/,
    /\bunion\b/,
    /\bselect\b.+\bfrom\b/,
    /\bdrop\b\s+\btable\b/,
    /\bor\b.+\=/,
  ];
  return patterns.some((re) => re.test(s));
}

function looksLikeXssPayload(input) {
  const s = String(input || "").toLowerCase();
  if (s.includes("[[sim_xss]]")) return true;
  const patterns = [/<\s*script\b/, /\bon\w+\s*=/, /javascript:/, /<\s*img\b[^>]*\bonerror\s*=/];
  return patterns.some((re) => re.test(s));
}

function unsafeLoginQueryExample(username, password) {
  const u = String(username || "");
  const p = String(password || "");
  return `SELECT * FROM users WHERE username = '${u}' AND password = '${p}'`;
}

function unsafeSearchQueryExample(term) {
  const t = String(term || "");
  return `SELECT id, username FROM users WHERE username LIKE '%${t}%'`;
}

async function audit(type, message, meta) {
  try {
    await db.logEvent(type, message, meta);
  } catch {
  }
}

app.use((req, res, next) => {
  if (!isLocalRequest(req)) {
    res.status(403).type("text/plain").send("VulnLab runs only on localhost.");
    return;
  }
  next();
});

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join("; ")
  );
  next();
});

app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(cookieParser());

const SESSION_COOKIE = "vl_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();

function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "Lax",
    secure: false,
    path: "/",
  };
}

function getMode(req) {
  return normalizeMode(req.cookies?.vl_mode);
}

function requireAuth(req, res, next) {
  if (!req.user) {
    res.redirect("/login");
    return;
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    res.redirect("/login");
    return;
  }
  if (!req.user.isAdmin) {
    res.status(403).type("text/plain").send("Forbidden: admin only.");
    return;
  }
  next();
}

app.use(async (req, _res, next) => {
  const cutoff = nowMs() - SESSION_TTL_MS;
  for (const [sid, s] of sessions.entries()) {
    if (s.createdAtMs < cutoff) sessions.delete(sid);
  }

  const sid = req.cookies?.[SESSION_COOKIE];
  if (!sid) return next();

  const sess = sessions.get(String(sid));
  if (!sess) return next();

  try {
    const user = await db.getUserById(sess.userId);
    if (!user) return next();
    req.user = user;
    return next();
  } catch (e) {
    return next();
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/dashboard", requireAuth, (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/profile", requireAuth, (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/admin", requireAdmin, (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

app.get("/api/mode", (req, res) => {
  res.json({ mode: getMode(req) });
});

app.post("/api/mode", (req, res) => {
  const mode = normalizeMode(req.body?.mode);
  res.cookie("vl_mode", mode, {
    httpOnly: false,
    sameSite: "Lax",
    secure: false,
    path: "/",
    maxAge: 365 * 24 * 60 * 60 * 1000,
  });
  audit("mode_change", `Mode set to ${mode}`, { mode }).catch(() => {});
  res.json({ mode });
});

app.post("/api/simulate", (req, res) => {
  const mode = getMode(req);
  const context = String(req.body?.context || "generic");
  const input = String(req.body?.input || "");

  const sqli = looksLikeSqlInjection(input);
  const xss = looksLikeXssPayload(input);

  let detected = false;
  let kind = "none";
  let impact = "LOW";
  let headline = "No suspicious pattern detected.";
  let details = "";
  let unsafeExample = null;
  let fix = null;

  if (sqli) {
    detected = true;
    kind = "SQLi";
    impact = "HIGH";
    headline = "Injection pattern detected.";
    details =
      "If an application builds SQL using string concatenation, attacker-controlled input can change the query logic.";
    unsafeExample = null;
    fix = null;
  } else if (xss) {
    detected = true;
    kind = "XSS";
    impact = "MEDIUM";
    headline = "XSS payload detected.";
    details =
      "If an application renders untrusted input as HTML/JS, an attacker could run scripts in a victim's browser.";
    unsafeExample = null;
    fix = null;
  }

  if (mode === "demo" && detected) {
    audit("simulation_detected", `${kind} pattern detected (context=${context})`, {
      kind,
      context,
      impact,
    }).catch(() => {});
  }

  res.json({
    mode,
    context,
    detected,
    kind,
    impact,
    output: {
      headline,
      details,
      unsafeExample,
      fix,
    },
  });
});

app.post("/api/signup", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (username.length < 3 || username.length > 32) {
    res.status(400).json({ error: "Username must be 3-32 characters." });
    return;
  }
  if (password.length < 6 || password.length > 72) {
    res.status(400).json({ error: "Password must be 6-72 characters." });
    return;
  }

  try {
    const user = await db.createUser({ username, password });
    audit("signup", "New user created", { username }).catch(() => {});
    res.json({ user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
  } catch (e) {
    if (String(e?.message || "").includes("UNIQUE")) {
      res.status(409).json({ error: "Username already exists." });
      return;
    }
    res.status(500).json({ error: "Server error." });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body?.username || "");
  const password = String(req.body?.password || "");
  const mode = getMode(req);

  audit("login_attempt", "Login attempt", { username }).catch(() => {});

  if (mode === "demo" && (looksLikeSqlInjection(username) || looksLikeSqlInjection(password))) {
    console.warn("⚠️ SQL Injection Attempt Detected", { username });
    audit("sqli_detected", "SQL injection pattern detected (login simulation)", { username }).catch(() => {});
    res.json({ ok: true, demo: { detected: true } });
    return;
  }

  try {
    const user = await db.verifyLogin({ username, password });
    if (!user) {
      audit("login_failed", "Login failed", { username }).catch(() => {});
      res.status(401).json({ error: "Invalid credentials." });
      return;
    }

    const sid = randomId(24);
    sessions.set(sid, { userId: user.id, createdAtMs: nowMs() });
    res.cookie(SESSION_COOKIE, sid, { ...sessionCookieOptions(), maxAge: SESSION_TTL_MS });

    audit("login_success", "Login success", { username: user.username }).catch(() => {});
    res.json({ ok: true, user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies?.[SESSION_COOKIE];
  if (sid) sessions.delete(String(sid));
  res.clearCookie(SESSION_COOKIE, sessionCookieOptions());
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, isAdmin: req.user.isAdmin } });
});

app.get("/api/session-info", requireAuth, (_req, res) => {
  res.json({
    cookie: {
      httpOnly: true,
      sameSite: "Lax",
      expiresIn: "8h",
    },
  });
});

app.get("/api/search", requireAuth, async (req, res) => {
  const term = String(req.query?.term || "");
  const mode = getMode(req);
  const detected = looksLikeSqlInjection(term);

  try {
    const results = await db.searchUsersByUsername(term);
    if (mode === "demo" && detected) {
      audit("sqli_detected", "SQL injection pattern detected (search simulation)", { term }).catch(() => {});
    }
    res.json({
      results,
    });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/users/lookup", requireAuth, async (req, res) => {
  const username = String(req.query?.username || "");
  const mode = getMode(req);
  const detected = looksLikeSqlInjection(username);

  try {
    const user = await db.getUserByUsername(username);
    if (mode === "demo" && detected) {
      audit("sqli_detected", "SQL injection pattern detected (lookup simulation)", { username }).catch(() => {});
    }
    res.json({
      user: user ? { id: user.id, username: user.username } : null,
    });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/profile", requireAuth, async (req, res) => {
  const requested = req.query?.id ? Number(req.query.id) : req.user.id;
  const wantsOther = Number.isFinite(requested) && requested !== req.user.id;

  const idor = wantsOther ? { detected: true, requestedId: requested, allowedId: req.user.id } : {};

  if (wantsOther) {
    audit("idor_attempt", "IDOR attempt simulated (requested other user)", {
      requestedId: requested,
      allowedId: req.user.id,
    }).catch(() => {});
  }

  res.json({
    profile: { id: req.user.id, username: req.user.username, bio: req.user.bio || "" },
    idor,
  });
});

app.post("/api/profile/bio", requireAuth, async (req, res) => {
  const bio = String(req.body?.bio || "");
  const mode = getMode(req);
  const xssDetected = looksLikeXssPayload(bio);

  try {
    if (mode === "secure" && xssDetected) {
      audit("xss_detected", "XSS payload blocked (bio)", { userId: req.user.id }).catch(() => {});
      res.status(400).json({ error: "Secure Mode blocked a suspected XSS payload in bio." });
      return;
    }

    const normalized = bio.slice(0, 600);
    await db.updateBio(req.user.id, normalized);
    if (mode === "demo" && xssDetected) {
      audit("xss_detected", "XSS payload detected (bio simulation)", { userId: req.user.id }).catch(() => {});
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/comments", requireAuth, async (_req, res) => {
  try {
    const comments = await db.listComments();
    res.json({ comments });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.post("/api/comments", requireAuth, async (req, res) => {
  const content = String(req.body?.content || "");
  const mode = getMode(req);
  const xssDetected = looksLikeXssPayload(content);

  try {
    if (mode === "secure" && xssDetected) {
      audit("xss_detected", "XSS payload blocked (comment)", { userId: req.user.id }).catch(() => {});
      res.status(400).json({ error: "Secure Mode blocked a suspected XSS payload in comment." });
      return;
    }

    await db.addComment({ userId: req.user.id, content: content.slice(0, 500), flagged: xssDetected ? 1 : 0 });
    if (mode === "demo" && xssDetected) {
      audit("xss_detected", "XSS payload detected (comment simulation)", { userId: req.user.id }).catch(() => {});
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/events", requireAuth, async (req, res) => {
  const afterId = Number(req.query?.after || 0);
  const limit = Number(req.query?.limit || 40);
  try {
    const events = await db.listEvents({ afterId, limit });
    const lastId = events.length ? events[events.length - 1].id : afterId;
    res.json({ events, lastId });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.post("/api/tool/run", requireAuth, async (req, res) => {
  const tool = String(req.body?.tool || "").toLowerCase().trim();
  const mode = getMode(req);

  const catalog = {
    sqlmap: {
      title: "SQLMap",
      domain: "Web / Database auditing",
      script: [
        "initializing audit module...",
        "target: localhost",
        "analyzing parameter handling...",
        "potential injection pattern flagged",
        "result: no data extracted",
      ],
    },
    nmap: {
      title: "Nmap",
      domain: "Network discovery",
      script: [
        "initializing scan engine...",
        "target: localhost",
        "probing common TCP ports...",
        "results: 80/tcp open http",
        "results: 3000/tcp open http-alt",
      ],
    },
    burp: {
      title: "Burp Suite",
      domain: "Web proxy / testing",
      script: [
        "starting intercept proxy...",
        "capturing request: POST /api/login",
        "analyzing headers and cookies...",
        "finding: secure cookie flags present (HttpOnly/SameSite)",
        "finding: suspicious input detected",
      ],
    },
    wireshark: {
      title: "Wireshark",
      domain: "Packet analysis",
      script: [
        "opening capture interface...",
        "filter: loopback traffic",
        "observed: HTTP requests to localhost:3000",
        "observed: request/response pairs",
      ],
    },
    metasploit: {
      title: "Metasploit Framework",
      domain: "Security testing framework",
      script: [
        "loading framework modules...",
        "selecting module category: auxiliary",
        "running safety checks...",
        "result: no exploitation performed",
      ],
    },
    john: {
      title: "John the Ripper",
      domain: "Password auditing",
      script: [
        "loading password audit dataset...",
        "evaluating password policy strength...",
        "result: weak passwords detected: 2",
        "result: reuse suspected: 1",
      ],
    },
    hashcat: {
      title: "Hashcat",
      domain: "Password auditing",
      script: [
        "initializing hash audit...",
        "checking hash algorithm labeling...",
        "result: legacy hashes detected: 1",
        "result: recommend stronger password hashing (bcrypt/argon2)",
      ],
    },
    nikto: {
      title: "Nikto",
      domain: "Web server auditing",
      script: [
        "initializing web audit...",
        "target: http://localhost",
        "checking headers and common misconfigs...",
        "finding: missing security headers on legacy endpoints",
      ],
    },
    zap: {
      title: "OWASP ZAP",
      domain: "Web application scanning",
      script: [
        "starting passive scan...",
        "observing requests to /api/search",
        "finding: input contains suspicious patterns",
        "finding: CSP present",
      ],
    },
    aircrack: {
      title: "Aircrack-ng",
      domain: "Wireless auditing",
      script: [
        "wireless auditing overview...",
      ],
    },
  };

  const entry = catalog[tool];
  if (!entry) {
    res.status(400).json({ error: "Unknown tool." });
    return;
  }

  const script = Array.isArray(entry.script) ? [...entry.script] : [];
  if (tool === "nmap") {
    const portSets = [
      ["80/tcp open http", "3000/tcp open http-alt"],
      ["22/tcp open ssh", "3000/tcp open http-alt"],
      ["443/tcp open https", "3000/tcp open http-alt"],
    ];
    const pick = portSets[Math.floor(Math.random() * portSets.length)];
    const base = script.filter((l) => !String(l).startsWith("results:"));
    script.length = 0;
    script.push(...base);
    for (let i = pick.length - 1; i >= 0; i--) {
      script.splice(3, 0, `results: ${pick[i]}`);
    }
  }
  if (tool === "nikto") {
    const findings = ["missing X-Content-Type-Options", "outdated server banner", "weak cache headers"];
    const f = findings[Math.floor(Math.random() * findings.length)];
    for (let i = 0; i < script.length; i++) {
      if (String(script[i]).startsWith("finding:")) script[i] = `finding: ${f}`;
    }
  }
  if (tool === "sqlmap") {
    const impact = ["Impact Level: HIGH", "Impact Level: MEDIUM"];
    script.splice(3, 0, impact[Math.floor(Math.random() * impact.length)]);
  }

  await audit("tool_run", `Toolkit simulation executed: ${entry.title}`, {
    tool,
    mode,
    userId: req.user.id,
  });

  res.json({
    tool,
    mode,
    title: entry.title,
    domain: entry.domain,
    script,
  });
});

app.get("/api/admin/users", requireAdmin, async (_req, res) => {
  try {
    const users = await db.listUsersAdminSafe();
    res.json({ users });
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/admin/stats", requireAdmin, async (_req, res) => {
  try {
    const stats = await db.getAdminStats();
    res.json(stats);
  } catch {
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/admin/analytics", requireAdmin, async (_req, res) => {
  res.json({
    analytics: [
      { label: "Logins today", value: 42 },
      { label: "SQLi attempts detected", value: 7 },
      { label: "XSS payloads flagged", value: 3 },
      { label: "IDOR attempts detected", value: 5 },
    ],
  });
});

app.get("/api/analyzer", requireAuth, (req, res) => {
  try {
    const files = {
      server: fs.readFileSync(path.join(__dirname, "server.js"), "utf8"),
      database: fs.readFileSync(path.join(__dirname, "database.js"), "utf8"),
      client: fs.readFileSync(path.join(__dirname, "public", "app.js"), "utf8"),
    };

    const checks = [];
    const issues = [];

    function pass(id, title, detail, fix) {
      checks.push({ id, title, status: "pass", detail, fix: fix || null });
    }

    function fail(id, title, severity, detail, fix) {
      const item = { id, title, status: "fail", severity, detail, fix };
      checks.push(item);
      issues.push(item);
    }

    const dbCallWithTemplate = /db\.(get|all|run)\(\s*`[^`]*\$\{[^}]+\}[^`]*`/m.test(files.server);
    const dbCallWithConcat = /db\.(get|all|run)\(\s*["'][^"']*["']\s*\+\s*/m.test(files.server);
    if (dbCallWithTemplate || dbCallWithConcat) {
      fail(
        "raw_sql",
        "Unsafe query construction detected",
        "HIGH",
        "A database call appears to build SQL using interpolation/concatenation. This can lead to SQL injection.",
        'Use parameterized queries, e.g. db.get("SELECT ... WHERE username = ? AND password = ?", [u, p]).'
      );
    } else {
      pass(
        "raw_sql",
        "Prepared statements / parameterization",
        "No DB calls appear to build SQL using interpolation/concatenation.",
        "Keep all SQL parameterized; validate inputs as data-shaping."
      );
    }

    const bcryptUsed = /bcrypt/.test(files.database) && /bcrypt\.hash/.test(files.database) && /bcrypt\.compare/.test(files.database);
    const plaintextPasswordColumn = /password\s+text/i.test(files.database);
    if (!bcryptUsed || plaintextPasswordColumn) {
      fail(
        "passwords",
        "Password storage risk",
        "HIGH",
        "Passwords should be stored as salted hashes (bcrypt/argon2). Plaintext or weak hashing is unsafe.",
        "Use bcrypt/argon2 for hashing and compare hashes server-side."
      );
    } else {
      pass("passwords", "Hashed passwords (bcrypt)", "bcrypt hashing and verification are present.");
    }

    const hasRequireAuth = /function requireAuth\(/.test(files.server);
    const dashboardGuarded = /app\.get\(\"\/dashboard\",\s*requireAuth/.test(files.server);
    const adminGuarded = /app\.get\(\"\/admin\",\s*requireAdmin/.test(files.server);
    if (!hasRequireAuth || !dashboardGuarded || !adminGuarded) {
      fail(
        "authz",
        "Authorization checks missing",
        "HIGH",
        "Protected routes should enforce authentication/authorization server-side.",
        "Add middleware guards (requireAuth/requireAdmin) to protected pages and APIs."
      );
    } else {
      pass("authz", "Route authorization checks", "Protected routes use requireAuth/requireAdmin guards.");
    }

    const cookieHttpOnly = /httpOnly:\s*true/.test(files.server);
    const cookieSameSite = /sameSite:\s*["']Lax["']/.test(files.server);
    if (!cookieHttpOnly || !cookieSameSite) {
      fail(
        "cookies",
        "Session cookie hardening",
        "MEDIUM",
        "Sessions should use HttpOnly and SameSite cookie flags to reduce common browser risks.",
        "Set HttpOnly=true and SameSite=Lax/Strict. Use Secure=true when on HTTPS."
      );
    } else {
      pass("cookies", "Secure cookie flags", "HttpOnly and SameSite cookie flags are set.");
    }

    const hasInnerHtml = /\.innerHTML\s*=/.test(files.client);
    if (hasInnerHtml) {
      checks.push({
        id: "innerhtml",
        title: "Potential XSS sink: innerHTML usage",
        status: "warn",
        severity: "LOW",
        detail: "innerHTML is present in the client. Ensure only constant templates are used, never untrusted input.",
        fix: "Prefer createElement/textContent or trusted templating that enforces encoding.",
      });
    } else {
      pass("innerhtml", "Safe DOM rendering", "No innerHTML assignments detected; textContent/encoding is preferred.");
    }

    const hasCsp = /Content-Security-Policy/.test(files.server);
    if (!hasCsp) {
      fail(
        "csp",
        "Content Security Policy",
        "MEDIUM",
        "CSP reduces XSS impact by restricting script sources.",
        "Add a strict CSP: script-src 'self' and avoid inline scripts."
      );
    } else {
      pass("csp", "Content Security Policy", "A CSP header is configured server-side.");
    }

    const localOnly = /VulnLab runs only on localhost/.test(files.server) && /isLocalRequest/.test(files.server);
    if (!localOnly) {
      fail(
        "localhost",
        "Localhost-only guard",
        "MEDIUM",
        "Learning labs should not be exposed to remote networks.",
        "Bind/guard requests to loopback only, and block non-local clients."
      );
    } else {
      pass("localhost", "Localhost-only guard", "Requests are blocked unless they originate from loopback.");
    }

    let score = 100;
    for (const i of issues) {
      if (i.severity === "HIGH") score -= 25;
      else if (i.severity === "MEDIUM") score -= 15;
      else score -= 5;
    }
    score = Math.max(0, Math.min(100, score));

    const summary = {
      score,
      mode: getMode(req),
      checkedFiles: ["server.js", "database.js", "public/app.js"],
      checks,
      issues,
    };

    audit("analyzer_run", "Security analyzer executed", { userId: req.user.id, score }).catch(() => {});
    res.json(summary);
  } catch (e) {
    res.status(500).json({ error: "Analyzer failed." });
  }
});

async function main() {
  await db.init();
  app.listen(PORT, () => {
    console.log(`VulnLab running on http://localhost:${PORT}`);
  });
}

main().catch((e) => {
  console.error("Startup failed:", e);
  process.exitCode = 1;
});
