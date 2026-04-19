/* global window, document, fetch, localStorage */

function qs(sel) {
  return document.querySelector(sel);
}

function qsa(sel) {
  return Array.from(document.querySelectorAll(sel));
}

function setText(el, text) {
  if (!el) return;
  el.textContent = String(text ?? "");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function timeStamp() {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...opts,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const message = data?.error || data?.message || `Request failed: ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function simulate(context, input) {
  try {
    return await api("/api/simulate", { method: "POST", body: JSON.stringify({ context, input }) });
  } catch {
    return null;
  }
}

function page() {
  const p = window.location.pathname;
  if (p === "/") return "home";
  if (p === "/login") return "login";
  if (p === "/dashboard" || p === "/profile") return "dashboard";
  if (p === "/admin") return "admin";
  return "other";
}

// ---- Sound (subtle WebAudio beeps; no external assets)
const Sound = (() => {
  let ctx = null;
  let enabled = false;

  function load() {
    enabled = localStorage.getItem("vl_sound") === "1";
  }

  function save() {
    localStorage.setItem("vl_sound", enabled ? "1" : "0");
  }

  function ensureCtx() {
    if (!ctx) {
      // Create lazily on user gesture.
      try {
        ctx = new (window.AudioContext || window.webkitAudioContext)();
      } catch {
        ctx = null;
      }
    }
    return ctx;
  }

  function beep({ freq = 880, dur = 0.045, gain = 0.018 } = {}) {
    if (!enabled) return;
    const c = ensureCtx();
    if (!c) return;
    const o = c.createOscillator();
    const g = c.createGain();
    o.type = "square";
    o.frequency.value = freq;
    g.gain.value = gain;
    o.connect(g);
    g.connect(c.destination);
    const t0 = c.currentTime;
    o.start(t0);
    o.stop(t0 + dur);
  }

  function toggle() {
    enabled = !enabled;
    save();
    beep({ freq: enabled ? 990 : 420, dur: 0.06, gain: 0.022 });
    return enabled;
  }

  function isEnabled() {
    return enabled;
  }

  load();
  return { beep, toggle, isEnabled };
})();

// ---- Terminal panel
const Terminal = (() => {
  const MAX = 250;
  const lines = [];
  let el = null;
  let statusEl = null;

  function bind() {
    el = qs("#terminalLog");
    statusEl = qs("#terminalStatus");
  }

  function status(text) {
    if (statusEl) statusEl.textContent = text;
  }

  function write(text) {
    const line = `[${timeStamp()}] ${text}`;
    lines.push(line);
    while (lines.length > MAX) lines.shift();
    if (el) {
      el.textContent = lines.join("\n");
      el.scrollTop = el.scrollHeight;
    }
  }

  function clear() {
    lines.length = 0;
    if (el) el.textContent = "";
  }

  return { bind, status, write, clear };
})();

// ---- Threat meter (simulated)
const Threat = (() => {
  let score = 0; // 0..100
  let decayTimer = null;

  function bind() {
    // no-op; uses ids directly in update()
  }

  function bump(kind) {
    if (kind === "sqli_detected") score = Math.min(100, score + 35);
    else if (kind === "xss_detected") score = Math.min(100, score + 22);
    else if (kind === "idor_attempt") score = Math.min(100, score + 18);
    else score = Math.min(100, score + 10);
    update();
  }

  function level() {
    if (score >= 70) return "High";
    if (score >= 35) return "Medium";
    return "Low";
  }

  function update() {
    const text = qs("#threatText");
    const dot = qs("#threatDot");
    if (text) text.textContent = `Threat: ${level()}`;
    if (dot) {
      dot.classList.remove("chip__dot--amber", "chip__dot--red");
      if (score >= 70) dot.classList.add("chip__dot--red");
      else if (score >= 35) dot.classList.add("chip__dot--amber");
    }
  }

  function startDecay() {
    if (decayTimer) return;
    decayTimer = window.setInterval(() => {
      score = Math.max(0, score - 2);
      update();
    }, 1200);
  }

  return { bind, bump, update, startDecay };
})();

// ---- Matrix background canvas
function initMatrixBackground() {
  const canvas = qs("#matrixBg");
  if (!canvas) return;
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduceMotion) return;

  const ctx = canvas.getContext("2d");
  const chars = "01ABCDEF#$%*+<>/\\|";
  let w = 0;
  let h = 0;
  let cols = 0;
  let drops = [];
  let last = 0;

  function resize() {
    w = (canvas.width = Math.floor(window.innerWidth * window.devicePixelRatio));
    h = (canvas.height = Math.floor(window.innerHeight * window.devicePixelRatio));
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    const fontSize = Math.max(12, Math.floor(14 * window.devicePixelRatio));
    ctx.font = `${fontSize}px ${getComputedStyle(document.body).fontFamily}`;
    cols = Math.floor(w / fontSize);
    drops = new Array(cols).fill(0).map(() => Math.floor(Math.random() * h));
  }

  function draw(ts) {
    if (!last) last = ts;
    const dt = ts - last;
    last = ts;

    // Fade frame
    ctx.fillStyle = "rgba(0, 0, 0, 0.06)";
    ctx.fillRect(0, 0, w, h);

    ctx.fillStyle = "rgba(0, 255, 156, 0.85)";
    const fontSize = Math.max(12, Math.floor(14 * window.devicePixelRatio));
    for (let i = 0; i < cols; i++) {
      const ch = chars[Math.floor(Math.random() * chars.length)];
      const x = i * fontSize;
      const y = drops[i];
      ctx.fillText(ch, x, y);
      const speed = 22 + (i % 6) * 3;
      drops[i] += (dt * speed) / 16.7;
      if (drops[i] > h + Math.random() * 1200) drops[i] = 0;
    }

    window.requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener("resize", resize);
  window.requestAnimationFrame(draw);
}

// ---- Boot overlay typing
async function showBootOverlay(lines) {
  const boot = qs("#boot");
  const out = qs("#bootLines");
  if (!boot || !out) return;

  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduceMotion) return;

  boot.classList.add("boot--open");
  out.textContent = "";
  for (const line of lines) {
    const full = `> ${line}\n`;
    for (let i = 0; i < full.length; i++) {
      out.textContent += full[i];
      if (full[i] !== "\n") Sound.beep({ freq: 640, dur: 0.02, gain: 0.01 });
      await sleep(10 + Math.random() * 14);
    }
    await sleep(70 + Math.random() * 90);
  }
  await sleep(300);
  boot.classList.remove("boot--open");
}

// ---- Mode toggle
function modeUi(mode) {
  const toggle = qs("#modeToggle");
  const label = qs("#modeLabel");
  if (toggle) toggle.checked = mode === "secure";
  if (label) label.textContent = `Mode: ${mode === "secure" ? "Secure" : "Demo"}`;
  const demoPill = qs("#demoPill");
  if (demoPill) demoPill.hidden = mode !== "demo";
}

async function loadMode() {
  try {
    const data = await api("/api/mode");
    modeUi(data.mode);
    return data.mode;
  } catch {
    modeUi("demo");
    return "demo";
  }
}

async function setMode(mode) {
  const data = await api("/api/mode", { method: "POST", body: JSON.stringify({ mode }) });
  modeUi(data.mode);
  Terminal.write(`mode set to ${data.mode}`);
  return data.mode;
}

function wireModeToggle() {
  const toggle = qs("#modeToggle");
  if (!toggle) return;
  toggle.addEventListener("change", async () => {
    const mode = toggle.checked ? "secure" : "demo";
    try {
      await setMode(mode);
      Sound.beep({ freq: mode === "secure" ? 920 : 660, dur: 0.06, gain: 0.018 });
    } catch {
      toggle.checked = !toggle.checked;
    }
  });
}

function wireSoundToggle() {
  const btn = qs("#soundToggle");
  if (!btn) return;
  btn.textContent = `Sound: ${Sound.isEnabled() ? "On" : "Off"}`;
  btn.addEventListener("click", () => {
    const on = Sound.toggle();
    btn.textContent = `Sound: ${on ? "On" : "Off"}`;
    Terminal.write(`sound ${on ? "enabled" : "disabled"}`);
  });
}

// ---- Shared actions
function wireLogout() {
  const btn = qs("#logoutBtn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    Terminal.write("logout requested");
    try {
      await api("/api/logout", { method: "POST" });
    } finally {
      window.location.href = "/login";
    }
  });
}

async function loadMe() {
  const data = await api("/api/me");
  const me = data.user;
  setText(qs("#meUser"), `${me.username} (#${me.id})`);
  const adminLink = qs("#adminLink");
  if (adminLink) adminLink.style.display = me.isAdmin ? "" : "none";
  Terminal.write(`authenticated as ${me.username}`);
  return me;
}

async function loadSessionInfo() {
  const pill = qs("#sessionPill");
  if (!pill) return;
  try {
    const data = await api("/api/session-info");
    setText(
      pill,
      `Session: HttpOnly=${data.cookie.httpOnly} SameSite=${data.cookie.sameSite} Expires=${data.cookie.expiresIn}`
    );
  } catch {
    setText(pill, "Session: unavailable");
  }
}

// ---- Events polling (server-side logs)
function startEventPolling() {
  const logEl = qs("#terminalLog");
  if (!logEl) return;
  let lastId = 0;
  let running = false;

  async function tick() {
    if (running) return;
    running = true;
    try {
      const data = await api(`/api/events?after=${encodeURIComponent(lastId)}&limit=40`);
      if (Array.isArray(data.events) && data.events.length) {
        for (const e of data.events) {
          const tag = e.type;
          Terminal.write(`server> [${tag}] ${e.message}`);
          if (tag === "sqli_detected" || tag === "xss_detected" || tag === "idor_attempt") {
            Threat.bump(tag);
          }
        }
        lastId = data.lastId || lastId;
      }
      Terminal.status("synced");
    } catch {
      Terminal.status("offline");
    } finally {
      running = false;
    }
  }

  Terminal.status("syncing");
  tick().catch(() => {});
  window.setInterval(() => tick().catch(() => {}), 2600);
}

// ---- Login / Signup
function wireAuthTabs() {
  const tabLogin = qs("#tabLogin");
  const tabSignup = qs("#tabSignup");
  const loginForm = qs("#loginForm");
  const signupForm = qs("#signupForm");
  if (!tabLogin || !tabSignup || !loginForm || !signupForm) return;

  function set(which) {
    if (which === "login") {
      tabLogin.classList.add("btn--primary");
      tabLogin.classList.remove("btn--ghost");
      tabSignup.classList.add("btn--ghost");
      tabSignup.classList.remove("btn--primary");
      signupForm.classList.add("hidden");
      loginForm.classList.remove("hidden");
    } else {
      tabSignup.classList.add("btn--primary");
      tabSignup.classList.remove("btn--ghost");
      tabLogin.classList.add("btn--ghost");
      tabLogin.classList.remove("btn--primary");
      loginForm.classList.add("hidden");
      signupForm.classList.remove("hidden");
    }
  }

  tabLogin.addEventListener("click", () => set("login"));
  tabSignup.addEventListener("click", () => set("signup"));
  set("login");
}

function wireQuickFill() {
  const btnAdmin = qs("#quickAdmin");
  const btnUser = qs("#quickUser");
  const btnTest = qs("#quickTest");
  if (!btnAdmin && !btnUser && !btnTest) return;

  const tabLogin = qs("#tabLogin");
  const usernameEl = qs("#loginForm input[name='username']");
  const passwordEl = qs("#loginForm input[name='password']");
  if (!usernameEl || !passwordEl) return;

  function fill(username, password) {
    tabLogin?.click();
    usernameEl.value = username;
    passwordEl.value = password;
    passwordEl.focus();
    Sound.beep({ freq: 720, dur: 0.04, gain: 0.016 });
    Terminal.write(`quick-fill: ${username}`);
  }

  btnAdmin?.addEventListener("click", () => fill("admin", "admin123"));
  btnUser?.addEventListener("click", () => fill("user", "password"));
  btnTest?.addEventListener("click", () => fill("test", "test123"));
}

function wireAuthForms() {
  const loginForm = qs("#loginForm");
  const signupForm = qs("#signupForm");
  const result = qs("#authResult");

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(loginForm);
      const payload = {
        username: (fd.get("username") || "").toString(),
        password: (fd.get("password") || "").toString(),
      };

      Terminal.write("scanning login input...");
      setText(result, "processing...");
      await sleep(350 + Math.random() * 350);

      try {
        const data = await api("/api/login", { method: "POST", body: JSON.stringify(payload) });
        if (data.demo?.detected) {
          Threat.bump("sqli_detected");
          Sound.beep({ freq: 520, dur: 0.08, gain: 0.02 });
          Terminal.write("login: input flagged");
          setText(result, "Input flagged. Adjust input and try again.");
          return;
        }

        if (!data.user?.username) throw new Error("Login failed.");
        Terminal.write(`login success for ${data.user.username}`);
        Sound.beep({ freq: 920, dur: 0.06, gain: 0.02 });
        setText(result, `Login successful. Redirecting...`);
        await sleep(250);
        window.location.href = "/dashboard";
      } catch (err) {
        Terminal.write(`login failed (${err.status || "?"})`);
        Sound.beep({ freq: 240, dur: 0.08, gain: 0.02 });
        setText(result, `Login failed: ${err.message}`);
      }
    });
  }

  if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(signupForm);
      const payload = {
        username: (fd.get("username") || "").toString(),
        password: (fd.get("password") || "").toString(),
      };

      Terminal.write("creating account...");
      setText(result, "processing...");
      await sleep(350 + Math.random() * 350);

      try {
        const data = await api("/api/signup", { method: "POST", body: JSON.stringify(payload) });
        Sound.beep({ freq: 740, dur: 0.06, gain: 0.02 });
        Terminal.write(`signup complete for ${data.user.username}`);
        setText(result, `Account created for ${data.user.username}. You can now login.`);
      } catch (err) {
        Sound.beep({ freq: 260, dur: 0.08, gain: 0.02 });
        Terminal.write(`signup failed (${err.status || "?"})`);
        setText(result, `Signup failed: ${err.message}`);
      }
    });
  }
}

// ---- Simulation engine panel
function wireSimulationEngine() {
  const form = qs("#simulateForm");
  const out = qs("#simulateResult");
  if (!form || !out) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const context = (fd.get("context") || "generic").toString();
    const input = (fd.get("input") || "").toString();

    Terminal.write("scanning input...");
    setText(out, "processing...");
    Terminal.status("processing");
    Sound.beep({ freq: 620, dur: 0.03, gain: 0.012 });
    await sleep(420 + Math.random() * 520);

    try {
      const data = await api("/api/simulate", { method: "POST", body: JSON.stringify({ context, input }) });
      if (data.detected) {
        const kind = data.kind === "SQLi" ? "sqli_detected" : data.kind === "XSS" ? "xss_detected" : "other";
        if (kind !== "other") Threat.bump(kind);
        Terminal.write("detecting anomalies...");
        Terminal.write("simulation output ready");
      } else {
        Terminal.write("no anomalies detected");
      }

      const lines = [];
      lines.push(data.detected ? "WARNING: suspicious pattern detected" : "OK: no suspicious pattern detected");
      lines.push(`Context: ${data.context}`);
      lines.push(`Mode: ${data.mode}`);
      lines.push(`Impact Level: ${data.impact}`);
      lines.push("");
      lines.push(data.output.headline);
      lines.push("");
      lines.push(data.output.details);
      if (data.output.unsafeExample) {
        lines.push("");
        lines.push("Example:");
        lines.push(String(data.output.unsafeExample));
      }
      if (data.output.fix) {
        lines.push("");
        lines.push("Mitigation:");
        lines.push(String(data.output.fix));
      }

      setText(out, lines.join("\n"));
      Terminal.status("idle");
    } catch (err) {
      setText(out, `Simulation failed: ${err.message}`);
      Terminal.status("idle");
    }
  });
}

// ---- SQLi lab actions
function wireSearch() {
  const form = qs("#searchForm");
  const out = qs("#searchResult");
  if (!form || !out) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const term = (fd.get("term") || "").toString();
    Terminal.write("search: scanning term...");
    setText(out, "processing...");
    await sleep(260 + Math.random() * 380);
    try {
      const data = await api(`/api/search?term=${encodeURIComponent(term)}`);
      const sim = await simulate("search", term);
      if (sim?.detected) {
        if (sim.kind === "SQLi") Threat.bump("sqli_detected");
        Sound.beep({ freq: 520, dur: 0.07, gain: 0.02 });
        Terminal.write("search: input flagged");
      } else {
        Terminal.write("search: ok");
      }

      const lines = [];
      if (sim?.detected) lines.push(`WARNING: ${sim.kind} pattern detected (impact: ${sim.impact})\n`);
      lines.push("Results:");
      lines.push(JSON.stringify(data.results, null, 2));
      setText(out, lines.join("\n"));
    } catch (err) {
      setText(out, `Search failed: ${err.message}`);
    }
  });
}

function wireLookup() {
  const form = qs("#lookupForm");
  const out = qs("#lookupResult");
  if (!form || !out) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const username = (fd.get("username") || "").toString();
    Terminal.write("lookup: scanning input...");
    setText(out, "processing...");
    await sleep(260 + Math.random() * 380);
    try {
      const data = await api(`/api/users/lookup?username=${encodeURIComponent(username)}`);
      const sim = await simulate("lookup", username);
      if (sim?.detected) {
        if (sim.kind === "SQLi") Threat.bump("sqli_detected");
        Sound.beep({ freq: 520, dur: 0.07, gain: 0.02 });
        Terminal.write("lookup: input flagged");
      } else {
        Terminal.write("lookup: ok");
      }

      const lines = [];
      if (sim?.detected) lines.push(`WARNING: ${sim.kind} pattern detected (impact: ${sim.impact})\n`);
      lines.push("Lookup result:");
      lines.push(JSON.stringify(data.user, null, 2));
      setText(out, lines.join("\n"));
    } catch (err) {
      setText(out, `Lookup failed: ${err.message}`);
    }
  });
}

// ---- XSS lab actions (safe rendering)
function wireComments() {
  const form = qs("#commentForm");
  const list = qs("#commentsList");
  const out = qs("#commentResult");
  if (!form || !list || !out) return;

  function renderComment(c) {
    const item = document.createElement("div");
    item.className = "missionCard";

    const head = document.createElement("div");
    head.className = "missionCard__head";

    const title = document.createElement("div");
    title.className = "missionCard__title";
    title.textContent = `${c.username} @ ${new Date(c.createdAt).toLocaleString()}`;

    const badge = document.createElement("span");
    badge.className = c.flagged ? "badge badge--amber" : "badge";
    badge.textContent = c.flagged ? "FLAGGED" : "OK";

    head.appendChild(title);
    head.appendChild(badge);

    const body = document.createElement("div");
    body.className = "missionCard__meta";
    // Safe: render as text only
    body.textContent = c.content;

    item.appendChild(head);
    item.appendChild(body);
    return item;
  }

  async function refresh() {
    const data = await api("/api/comments");
    list.innerHTML = "";
    for (const c of data.comments) {
      list.appendChild(renderComment(c));
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const content = (fd.get("content") || "").toString();
    Terminal.write("comment: scanning payload...");
    setText(out, "processing...");
    await sleep(240 + Math.random() * 420);
    try {
      await api("/api/comments", { method: "POST", body: JSON.stringify({ content }) });
      const sim = await simulate("comment", content);
      if (sim?.detected && sim.kind === "XSS") {
        Threat.bump("xss_detected");
        Sound.beep({ freq: 560, dur: 0.07, gain: 0.02 });
        Terminal.write("comment: input flagged");
        setText(out, "Input flagged.");
      } else {
        Terminal.write("comment: posted");
        setText(out, "Comment posted.");
      }
      form.reset();
      await refresh();
    } catch (err) {
      Terminal.write("comment: blocked or failed");
      setText(out, `Comment failed: ${err.message}`);
    }
  });

  refresh().catch(() => {});
}

// ---- IDOR + profile
async function loadProfileAndIdorNotice() {
  const out = qs("#idorResult");
  const idEl = qs("#profileId");
  const userEl = qs("#profileUsername");
  const bioArea = qs("textarea[name='bio']");
  if (!out || !idEl || !userEl || !bioArea) return;

  const params = new URLSearchParams(window.location.search);
  const requestedId = params.get("id");

  Terminal.write("profile: loading...");
  const data = await api(`/api/profile${requestedId ? `?id=${encodeURIComponent(requestedId)}` : ""}`);

  if (data.idor?.detected) {
    Threat.bump("idor_attempt");
    Sound.beep({ freq: 610, dur: 0.06, gain: 0.02 });
    Terminal.write("idor: access flagged");
    setText(out, `Access blocked.\nrequested: ${data.idor.requestedId}\nallowed: ${data.idor.allowedId}`);
  } else {
    setText(out, "OK.");
  }

  setText(idEl, data.profile.id);
  setText(userEl, data.profile.username);
  bioArea.value = data.profile.bio || "";
}

function wireBio() {
  const form = qs("#bioForm");
  const out = qs("#bioResult");
  if (!form || !out) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const bio = (fd.get("bio") || "").toString();
    Terminal.write("bio: scanning payload...");
    setText(out, "processing...");
    await sleep(260 + Math.random() * 380);
    try {
      await api("/api/profile/bio", { method: "POST", body: JSON.stringify({ bio }) });
      const sim = await simulate("bio", bio);
      if (sim?.detected && sim.kind === "XSS") {
        Threat.bump("xss_detected");
        Sound.beep({ freq: 560, dur: 0.07, gain: 0.02 });
        Terminal.write("bio: input flagged");
        setText(out, "Input flagged.");
      } else {
        Terminal.write("bio: updated");
        setText(out, "Bio updated.");
      }
    } catch (err) {
      Terminal.write("bio: blocked or failed");
      setText(out, `Bio update failed: ${err.message}`);
    }
  });
}

// ---- Tools modal
function wireToolCards() {
  const modal = qs("#toolModal");
  const close = qs("#toolModalClose");
  const title = qs("#toolModalTitle");
  const body = qs("#toolModalBody");
  if (!modal || !close || !title || !body) return;

  const tools = {
    sqlmap: {
      name: "SQLMap",
      where: "Web / database auditing",
      what: "Automation-focused SQL injection auditing tool.",
      workflow: "Identify inputs · Observe behavior · Validate defenses",
      simulated: "testing parameter handling...\npotential injection pattern flagged\nresult: no data extracted",
      defense: "Prepared statements · Validation · Least privilege · Monitoring",
    },
    nmap: {
      name: "Nmap",
      where: "Network discovery / exposure assessment",
      what: "Discovers reachable services and exposed ports.",
      workflow: "Discover exposed services · Build inventory · Reduce attack surface",
      simulated: "target: localhost\nprobing common ports...\nports detected: 80, 3000",
      defense: "Firewalls · Disable unused services · Segmentation · Inventory",
    },
    burp: {
      name: "Burp Suite",
      where: "Web testing / proxy inspection",
      what: "Intercepting proxy to inspect requests, cookies, and auth flows.",
      workflow: "Intercept traffic · Inspect cookies/headers · Validate auth/session design",
      simulated: "capturing request: POST /api/login\nanalyzing cookies...\nfinding: secure flags present",
      defense: "HttpOnly+SameSite cookies · CSRF defenses · Secure session design",
    },
    wireshark: {
      name: "Wireshark",
      where: "Network troubleshooting / analysis",
      what: "Packet capture and protocol analysis.",
      workflow: "Capture traffic · Filter flows · Inspect protocol behavior",
      simulated: "filter: loopback\nobserved: HTTP request/response pairs\nlatency spikes",
      defense: "TLS where applicable · Segmentation · Baselines and monitoring",
    },
    metasploit: {
      name: "Metasploit Framework",
      where: "Security testing framework",
      what: "Framework for organizing test modules.",
      workflow: "Model threats · Validate hardening · Practice detection/response",
      simulated: "loading modules...\nsafety checks...\nresult: no exploitation performed",
      defense: "Patch management · Hardening · Monitoring · Least privilege",
    },
    john: {
      name: "John the Ripper",
      where: "Password auditing",
      what: "Audits password policy strength and weak credentials.",
      workflow: "Audit policy · Identify weak/reused passwords · Improve controls",
      simulated: "evaluating policy strength...\nweak passwords detected: 2\nrecommend MFA",
      defense: "MFA · Rate limiting · Strong hashing · Credential stuffing defenses",
    },
    hashcat: {
      name: "Hashcat",
      where: "Password auditing",
      what: "Audits password storage practices and risk awareness.",
      workflow: "Review hash policies · Upgrade algorithms · Enforce strong auth",
      simulated: "legacy hashes detected: 1\nrecommend slow hashes",
      defense: "bcrypt/argon2 · Salt · MFA · Monitoring",
    },
    nikto: {
      name: "Nikto",
      where: "Web server auditing",
      what: "Checks for common web server misconfigurations and risky settings.",
      workflow: "Identify surface · Check misconfigs · Fix headers/patches/config",
      simulated: "checking headers...\nfinding: missing hardening header\nrecommend patching",
      defense: "Security headers · Patch management · Reduce attack surface",
    },
    zap: {
      name: "OWASP ZAP",
      where: "Web app scanning",
      what: "Scanner/proxy to help identify defensive gaps and verify mitigations.",
      workflow: "Passive observe · Targeted tests · Fix and re-validate",
      simulated: "passive scan...\nfinding: suspicious input patterns\nCSP present",
      defense: "Validation · Encoding · CSP · Authz checks · Monitoring",
    },
    aircrack: {
      name: "Aircrack-ng",
      where: "Wireless auditing",
      what: "Wireless assessment suite.",
      workflow: "Assess configuration · Verify encryption/policies · Improve monitoring and hardening",
      simulated: "wireless auditing overview...\ndefense: WPA2/3 + disable WPS",
      defense: "WPA2/3 · Strong passphrases · Disable WPS · Monitor AP logs",
    },
  };

  async function runToolSimulation(toolKey) {
    const status = qs("#toolSimStatus");
    const log = qs("#toolSimLog");
    if (!status || !log) return;

    Terminal.write(`toolkit: initializing ${toolKey} simulation...`);
    status.textContent = "processing";
    log.textContent = "> initializing...\n";
    Sound.beep({ freq: 700, dur: 0.03, gain: 0.012 });

    await sleep(260 + Math.random() * 420);
    try {
      const data = await api("/api/tool/run", { method: "POST", body: JSON.stringify({ tool: toolKey }) });
      status.textContent = "ready";
      const lines = [];
      lines.push(`> tool: ${data.title}`);
      lines.push(`> domain: ${data.domain}`);
      lines.push(`> mode: ${data.mode}`);
      lines.push("");
      for (const s of data.script || []) lines.push(`> ${s}`);
      log.textContent = lines.join("\n");
      Terminal.write(`toolkit: simulation ready (${data.title})`);
      Sound.beep({ freq: 860, dur: 0.05, gain: 0.018 });
    } catch (err) {
      status.textContent = "error";
      log.textContent = `> error: ${err.message}`;
      Terminal.write("toolkit: simulation failed");
    }
  }

  function openTool(key) {
    const t = tools[key];
    if (!t) return;
    title.textContent = t.name.toUpperCase();
    body.textContent = [
      `What it does: ${t.what}`,
      `Where it's used: ${t.where}`,
      `Typical workflow: ${t.workflow}`,
      "",
      "Example output:",
      t.simulated,
      "",
      `Defensive perspective: ${t.defense}`,
    ].join("\n");
    modal.classList.add("modal--open");
    modal.setAttribute("aria-hidden", "false");
    Sound.beep({ freq: 720, dur: 0.05, gain: 0.02 });
    Terminal.write(`opened tool: ${t.name}`);
    runToolSimulation(key).catch(() => {});
  }

  function closeTool() {
    modal.classList.remove("modal--open");
    modal.setAttribute("aria-hidden", "true");
  }

  close.addEventListener("click", closeTool);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeTool();
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeTool();
  });

  qsa("[data-tool]").forEach((btn) => {
    btn.addEventListener("click", () => openTool(btn.getAttribute("data-tool")));
  });
}

// ---- Admin
function drawBarChart(canvas, labels, values) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const targetW = Math.max(300, Math.floor(rect.width * dpr));
  const targetH = Math.max(160, Math.floor(rect.height * dpr));
  if (canvas.width !== targetW) canvas.width = targetW;
  if (canvas.height !== targetH) canvas.height = targetH;
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const pad = 18;
  const chartW = w - pad * 2;
  const chartH = h - pad * 2;
  const maxV = Math.max(1, ...values);

  // background
  ctx.fillStyle = "rgba(0,0,0,0.12)";
  ctx.fillRect(0, 0, w, h);

  // grid
  ctx.strokeStyle = "rgba(0,255,156,0.10)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad + (chartH * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(pad + chartW, y);
    ctx.stroke();
  }

  const barGap = 10;
  const barW = Math.floor((chartW - barGap * (labels.length - 1)) / labels.length);

  ctx.font = "12px " + getComputedStyle(document.body).fontFamily;
  for (let i = 0; i < labels.length; i++) {
    const v = values[i];
    const x = pad + i * (barW + barGap);
    const bh = Math.floor((v / maxV) * (chartH - 26));
    const y = pad + chartH - bh - 18;

    const isBad = labels[i].toLowerCase().includes("sqli") || labels[i].toLowerCase().includes("xss") || labels[i].toLowerCase().includes("idor");
    ctx.fillStyle = isBad ? "rgba(255,0,60,0.38)" : "rgba(0,255,156,0.26)";
    ctx.fillRect(x, y, barW, bh);
    ctx.strokeStyle = isBad ? "rgba(255,0,60,0.65)" : "rgba(0,255,156,0.55)";
    ctx.strokeRect(x, y, barW, bh);

    ctx.fillStyle = "rgba(231,255,246,0.84)";
    ctx.fillText(String(v), x + 4, y - 4);

    ctx.fillStyle = "rgba(231,255,246,0.66)";
    ctx.fillText(labels[i], x, pad + chartH);
  }
}

async function loadAdmin() {
  const notice = qs("#adminNotice");
  const statsEl = qs("#adminStats");
  const users = qs("#adminUsers");
  const analytics = qs("#adminAnalytics");
  const chart = qs("#adminChart");
  if (!notice || !statsEl || !users || !analytics) return;

  const [mode, u, a, s] = await Promise.all([
    api("/api/mode"),
    api("/api/admin/users"),
    api("/api/admin/analytics"),
    api("/api/admin/stats"),
  ]);

  if (mode.mode === "demo") {
    setText(notice, "DEMO MODE: Admin access is still protected by role checks.");
  } else {
    setText(notice, "SECURE MODE: Admin access is protected by role checks.");
  }

  const t = s.totals;
  setText(
    statsEl,
    [
      "Totals:",
      `- users: ${t.users}`,
      `- comments: ${t.comments}`,
      `- login attempts: ${t.loginAttempts}`,
      `- login success: ${t.loginSuccess}`,
      `- toolkit runs: ${t.toolRuns}`,
      `- sqli detected: ${t.sqliDetected}`,
      `- xss detected: ${t.xssDetected}`,
      `- idor attempts: ${t.idorAttempts}`,
      `- events: ${t.events}`,
    ].join("\n")
  );

  // Draw chart from totals (safe)
  drawBarChart(
    chart,
    ["logins", "tools", "sqli", "xss", "idor"],
    [t.loginAttempts, t.toolRuns, t.sqliDetected, t.xssDetected, t.idorAttempts]
  );

  users.innerHTML = "";
  for (const user of u.users) {
    const item = document.createElement("div");
    item.className = "missionCard";
    const head = document.createElement("div");
    head.className = "missionCard__head";
    const title = document.createElement("div");
    title.className = "missionCard__title";
    title.textContent = `${user.username} (#${user.id})${user.isAdmin ? " - admin" : ""}`;
    const badge = document.createElement("span");
    badge.className = user.isAdmin ? "badge badge--red" : "badge";
    badge.textContent = user.isAdmin ? "ADMIN" : "USER";
    head.appendChild(title);
    head.appendChild(badge);
    const body = document.createElement("div");
    body.className = "missionCard__meta";
    body.textContent = `password_hash: ${user.passwordHash}`;
    item.appendChild(head);
    item.appendChild(body);
    users.appendChild(item);
  }

  analytics.innerHTML = "";
  for (const row of a.analytics) {
    const item = document.createElement("div");
    item.className = "missionCard";
    const head = document.createElement("div");
    head.className = "missionCard__head";
    const title = document.createElement("div");
    title.className = "missionCard__title";
    title.textContent = row.label;
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "DUMMY";
    head.appendChild(title);
    head.appendChild(badge);
    const body = document.createElement("div");
    body.className = "missionCard__meta";
    body.textContent = String(row.value);
    item.appendChild(head);
    item.appendChild(body);
    analytics.appendChild(item);
  }
}

// ---- Home helpers
function initHome() {
  const status = qs("#homeStatus");
  if (!status) return;
  setText(
    status,
    [
      "Initializing system...",
      "Loading simulation engine...",
      "Enforcing localhost-only access...",
      "Ready.",
      "",
      "Enter the lab to begin.",
    ].join("\n")
  );
}

async function initAuthLabPanel() {
  const out = qs("#authLabResult");
  if (!out) return;
  setText(
    out,
    [
      "Auth status:",
      "- passwords: bcrypt hashed (server-side)",
      "- sessions: HttpOnly + SameSite cookies",
    ].join("\n")
  );
}

async function initLearningIntro() {
  const out = qs("#learningIntro");
  if (!out) return;
  setText(
    out,
    [
      "Reference loaded.",
    ].join("\n")
  );
}

async function initDefenseIntro() {
  const out = qs("#defenseIntro");
  if (!out) return;
  setText(
    out,
    [
      "Defense panel loaded.",
    ].join("\n")
  );
}

function setLiveAnalyzer(lines) {
  const out = qs("#liveAnalyzerBox");
  if (!out) return;
  setText(out, Array.isArray(lines) ? lines.join("\n") : String(lines || ""));
}

async function runLiveAnalysis({ context, input }) {
  if (!qs("#liveAnalyzerBox")) return;
  try {
    const data = await api("/api/simulate", { method: "POST", body: JSON.stringify({ context, input }) });
    const lines = [];
    lines.push("Input Analysis");
    lines.push(`- context: ${data.context}`);
    lines.push(`- mode: ${data.mode}`);
    lines.push(`- detected: ${data.detected ? "yes" : "no"}`);
    lines.push(`- issue type: ${data.kind}`);
    lines.push(`- impact: ${data.impact}`);
    lines.push("");
    lines.push(data.output.headline);
    lines.push("");
    lines.push(data.output.details);
    if (data.output.fix) {
      lines.push("");
      lines.push("How a secure system handles this:");
      lines.push(data.output.fix);
    }
    setLiveAnalyzer(lines);
  } catch {
    // keep quiet
  }
}

function showLevelUp(level) {
  const el = qs("#levelUp");
  const sub = qs("#levelUpSub");
  if (!el || !sub) return;
  sub.textContent = `New level reached: Level ${level}`;
  el.classList.add("levelUp--open");
  Sound.beep({ freq: 980, dur: 0.08, gain: 0.02 });
  Terminal.write(`level up: ${level}`);
  window.setTimeout(() => el.classList.remove("levelUp--open"), 1100);
}

function wireAnalyzer() {
  const btn = qs("#runAnalyzerBtn");
  const scoreText = qs("#securityScoreText");
  const summary = qs("#analyzerSummary");
  const findings = qs("#analyzerFindings");
  const widgetScore = qs("#widgetScore");
  if (!btn || !summary || !findings || !scoreText) return;

  btn.addEventListener("click", async () => {
    setText(summary, "Running analyzer...");
    findings.innerHTML = "";
    try {
      const data = await api("/api/analyzer");
      const score = data.score;
      scoreText.textContent = String(score);
      if (widgetScore) widgetScore.textContent = String(score);

      const lines = [];
      lines.push("Security Analyzer Report");
      lines.push(`- score: ${score}/100`);
      lines.push(`- checked files: ${(data.checkedFiles || []).join(", ")}`);
      lines.push(`- issues: ${(data.issues || []).length}`);
      lines.push("");
      lines.push("Notes:");
      lines.push("- This is a static/self-check report; it does not attempt exploitation.");
      setText(summary, lines.join("\n"));

      for (const c of data.checks || []) {
        const card = document.createElement("div");
        card.className = "missionCard";
        const head = document.createElement("div");
        head.className = "missionCard__head";
        const t = document.createElement("div");
        t.className = "missionCard__title";
        t.textContent = c.title;
        const badge = document.createElement("span");
        const status = c.status || "pass";
        badge.className = status === "fail" ? "badge badge--red" : status === "warn" ? "badge badge--amber" : "badge";
        badge.textContent = status.toUpperCase();
        head.appendChild(t);
        head.appendChild(badge);

        const meta = document.createElement("div");
        meta.className = "missionCard__meta";
        const parts = [];
        if (c.detail) parts.push(c.detail);
        if (c.fix) parts.push(`Fix: ${c.fix}`);
        meta.textContent = parts.join("\n\n");

        card.appendChild(head);
        card.appendChild(meta);
        findings.appendChild(card);
      }

      Terminal.write(`analyzer: score ${score}`);
      Sound.beep({ freq: 820, dur: 0.06, gain: 0.02 });
    } catch (err) {
      setText(summary, `Analyzer failed: ${err.message}`);
      Terminal.write("analyzer: failed");
    }
  });
}

async function initGuideIntro() {
  const out = qs("#guideIntro");
  if (!out) return;
  setText(
    out,
    [
      "Guide loaded.",
    ].join("\n")
  );
}

function wireChallenges() {
  const listEl = qs("#challengeList");
  const detailEl = qs("#challengeDetail");
  const hintBtn = qs("#hintBtn");
  const markBtn = qs("#markUnderstoodBtn");
  const hintBox = qs("#challengeHintBox");
  const outcomeBox = qs("#challengeOutcomeBox");
  const completionBox = qs("#challengeCompletionBox");
  const resetBtn = qs("#challengeReset");

  const xpText = qs("#xpText");
  const xpLevel = qs("#xpLevel");
  const xpBar = qs("#xpBar");
  const progText = qs("#challengeProgressText");

  if (!listEl || !detailEl || !hintBtn || !markBtn || !hintBox || !outcomeBox || !completionBox || !resetBtn) return;

  const XP_PER_COMPLETE = 40;
  const XP_PER_EVIDENCE = 8;
  const XP_PER_HINT = 3;
  const XP_PER_LEVEL = 100;

  const challenges = [
    {
      id: "c1_sqli_login",
      title: "CHALLENGE 1: SQL Injection (Login)",
      task: "Try to understand how unsafe queries behave during login (simulation).",
      what: ["Interact with the login form", "Observe behavior when input changes", "Use [[SIM_SQLI]] to trigger safe analysis"],
      hints: [
        "Check how input is used in backend query.",
        "Does the query treat input as data or code?",
        "Look for differences in response when input changes.",
      ],
      expected: [
        "In insecure systems, improper input handling can alter query logic.",
        "Secure systems prevent this using parameterized queries.",
      ],
      evidence: [{ kind: "SQLi", contexts: ["login"] }],
    },
    {
      id: "c2_xss_comments",
      title: "CHALLENGE 2: XSS (Comments)",
      task: "Test how user input is rendered in the UI (safe simulation).",
      what: ["Post a comment", "Observe safe rendering (encoded output)", "Use [[SIM_XSS]] to trigger safe analysis"],
      hints: ["Is input encoded before display?", "Where is the data injected in HTML?"],
      expected: ["Unsafe rendering allows script execution.", "Safe systems encode output and avoid unsafe DOM sinks."],
      evidence: [{ kind: "XSS", contexts: ["comment"] }],
    },
    {
      id: "c3_idor",
      title: "CHALLENGE 3: IDOR",
      task: "Explore how user IDs control access and why server-side authorization matters.",
      what: ["Visit /profile?id=YOUR_ID", "Change the id value", "Observe the warning and safe response"],
      hints: ["Try modifying identifiers.", "Does backend verify ownership?"],
      expected: [
        "Access control must be enforced server-side.",
        "Never trust URL identifiers without authorization checks.",
      ],
      evidence: [{ kind: "IDOR", contexts: ["idor"] }],
    },
    {
      id: "c4_auth_session",
      title: "CHALLENGE 4: AUTH & SESSION",
      task: "Analyze login/session behavior and understand secure session handling.",
      what: ["Review session info", "Logout and re-check protected pages", "Observe cookie flags and invalidation"],
      hints: [
        "What happens after logout?",
        "Are cookies HttpOnly + SameSite?",
        "What is stored server-side vs client-side?",
      ],
      expected: [
        "Secure sessions should expire and be invalidated on logout.",
        "Cookies should use HttpOnly + SameSite, and Secure on HTTPS.",
      ],
      evidence: [{ kind: "SESSION", contexts: ["session_info"] }],
    },
  ];

  const STORAGE_KEY = "vl_challenges_state_v3";
  const XP_KEY = "vl_xp_v3";

  function loadState() {
    let s = null;
    try {
      s = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    } catch {
      s = null;
    }
    if (!s || typeof s !== "object") s = {};
    return s;
  }

  function saveState(s) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  }

  function getXp() {
    const x = Number(localStorage.getItem(XP_KEY) || "0");
    return Number.isFinite(x) ? Math.max(0, x) : 0;
  }

  function setXp(x) {
    localStorage.setItem(XP_KEY, String(Math.max(0, Math.floor(x))));
  }

  function levelForXp(xp) {
    return Math.floor(xp / XP_PER_LEVEL) + 1;
  }

  function updateXpUi() {
    const xp = getXp();
    const level = levelForXp(xp);
    const base = Math.floor(xp / XP_PER_LEVEL) * XP_PER_LEVEL;
    const pct = Math.max(0, Math.min(100, Math.floor(((xp - base) / XP_PER_LEVEL) * 100)));
    if (xpText) xpText.textContent = `XP: ${xp}`;
    if (xpLevel) xpLevel.textContent = `Level ${level}`;
    if (xpBar) xpBar.style.width = `${pct}%`;
  }

  function awardXp(delta) {
    const before = getXp();
    const beforeLevel = levelForXp(before);
    const after = before + delta;
    setXp(after);
    updateXpUi();
    const afterLevel = levelForXp(after);
    if (afterLevel > beforeLevel) showLevelUp(afterLevel);
  }

  function stateFor(id) {
    const s = loadState();
    if (!s[id]) s[id] = { hintsShown: 0, understood: false, evidence: 0 };
    return s[id];
  }

  function updateProgressUi() {
    const s = loadState();
    const completed = challenges.filter((c) => s[c.id]?.understood).length;
    if (progText) progText.textContent = `Progress: ${completed}/${challenges.length}`;

    const widgetChallenges = qs("#widgetChallenges");
    const widgetConcepts = qs("#widgetConcepts");
    if (widgetChallenges) widgetChallenges.textContent = String(completed);
    if (widgetConcepts) widgetConcepts.textContent = String(completed);
  }

  let activeId = challenges[0].id;

  function renderList() {
    const s = loadState();
    listEl.innerHTML = "";
    for (const c of challenges) {
      const st = s[c.id] || { understood: false };
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "missionCard" + (c.id === activeId ? " challengeActive" : "");
      btn.innerHTML =
        '<div class="missionCard__head"><div class="missionCard__title"></div><span class="badge"></span></div><div class="missionCard__meta"></div>';
      btn.querySelector(".missionCard__title").textContent = c.title;
      btn.querySelector(".missionCard__meta").textContent = c.task;
      btn.querySelector(".badge").textContent = st.understood ? "DONE" : "OPEN";
      btn.querySelector(".badge").className = st.understood ? "badge" : "badge badge--amber";
      btn.addEventListener("click", () => select(c.id));
      listEl.appendChild(btn);
    }
  }

  function writeDetail(c) {
    const st = stateFor(c.id);
    const lines = [];
    lines.push(c.title);
    lines.push("");
    lines.push("Task:");
    lines.push(`- ${c.task}`);
    lines.push("");
    lines.push("What you should do:");
    for (const d of c.what) lines.push(`- ${d}`);
    lines.push("");
    lines.push(`Hints revealed: ${st.hintsShown}/${c.hints.length}`);
    lines.push(`Evidence observed: ${st.evidence}`);
    lines.push(`Completion: ${st.understood ? "CONCEPT UNDERSTOOD" : "in progress"}`);
    setText(detailEl, lines.join("\n"));

    setText(outcomeBox, ["Expected Outcome:"].concat(c.expected.map((x) => `- ${x}`)).join("\n"));

    setText(
      completionBox,
      st.understood
        ? "Completion:\n- CONCEPT UNDERSTOOD"
        : "Completion:\n- Mark Concept Understood when you feel ready."
    );
  }

  function select(id) {
    activeId = id;
    renderList();
    setText(hintBox, "Hints:\n- Press 'Reveal Hint' to show the next hint.");
    const c = challenges.find((x) => x.id === id) || challenges[0];
    writeDetail(c);
  }

  function revealHint() {
    const c = challenges.find((x) => x.id === activeId);
    if (!c) return;
    const s = loadState();
    const st = stateFor(c.id);
    if (st.hintsShown >= c.hints.length) {
      setText(hintBox, "Hints:\n- No more hints.");
      return;
    }
    st.hintsShown += 1;
    s[c.id] = st;
    saveState(s);

    const shown = c.hints.slice(0, st.hintsShown).map((h, i) => `- Hint ${i + 1}: ${h}`);
    setText(hintBox, ["Hints:"].concat(shown).join("\n"));
    awardXp(XP_PER_HINT);
    Terminal.write(`challenge: hint revealed (${c.id})`);
    writeDetail(c);
  }

  function complete(reason) {
    const c = challenges.find((x) => x.id === activeId);
    if (!c) return;
    const s = loadState();
    const st = stateFor(c.id);
    if (st.understood) return;
    st.understood = true;
    s[c.id] = st;
    saveState(s);
    awardXp(XP_PER_COMPLETE);
    Sound.beep({ freq: 920, dur: 0.06, gain: 0.02 });
    Terminal.write(`challenge: completed (${c.id})`);
    setText(completionBox, `Completion:\n- CONCEPT UNDERSTOOD\n- ${reason || "Nice work."}`);
    renderList();
    updateProgressUi();
    writeDetail(c);
  }

  function markUnderstood() {
    complete("Marked completed.");
  }

  function addEvidence(kind, context) {
    const c = challenges.find((x) => x.id === activeId);
    if (!c) return;
    const s = loadState();
    const st = stateFor(c.id);
    st.evidence += 1;
    s[c.id] = st;
    saveState(s);
    awardXp(XP_PER_EVIDENCE);
    writeDetail(c);

    const matches = (c.evidence || []).some((e) => e.kind === kind && (e.contexts || []).includes(context));
    if (matches) complete("Evidence observed during simulation.");
  }

  window.__vlChallenges = { addEvidence, getActive: () => activeId };

  resetBtn.addEventListener("click", () => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(XP_KEY);
    Terminal.write("challenge: reset progress");
    Sound.beep({ freq: 360, dur: 0.06, gain: 0.02 });
    activeId = challenges[0].id;
    updateXpUi();
    updateProgressUi();
    renderList();
    select(activeId);
  });

  hintBtn.addEventListener("click", revealHint);
  markBtn.addEventListener("click", markUnderstood);

  // init
  updateXpUi();
  updateProgressUi();
  renderList();
  select(activeId);
}

// ---- Boot
async function boot() {
  Terminal.bind();
  Threat.bind();
  Threat.update();
  Threat.startDecay();
  initMatrixBackground();
  wireSoundToggle();

  const p = page();
  if (p === "home") {
    Terminal.write("welcome console online");
    initHome();
    await showBootOverlay(["initializing system...", "calibrating sensors...", "ready"]);
    await loadMode();
    wireModeToggle();
    return;
  }

  await loadMode();
  wireModeToggle();

  if (p === "login") {
    Terminal.write("gateway online");
    await showBootOverlay(["handshake...", "verifying environment...", "awaiting credentials"]);
    wireAuthTabs();
    wireAuthForms();
    wireQuickFill();
    return;
  }

  if (p === "dashboard") {
    wireLogout();
    await showBootOverlay(["loading dashboard...", "syncing event stream...", "modules online"]);
    await loadMe();
    await loadSessionInfo();
    wireSimulationEngine();
    wireSearch();
    wireLookup();
    wireComments();
    await loadProfileAndIdorNotice();
    wireBio();
    wireToolCards();
    await initAuthLabPanel();
    await initLearningIntro();
    await initDefenseIntro();
    wireChallenges();
    startEventPolling();
    return;
  }

  if (p === "admin") {
    wireLogout();
    await showBootOverlay(["elevating privileges...", "loading telemetry...", "admin console ready"]);
    startEventPolling();
    await loadAdmin();
    return;
  }
}

boot().catch(() => {
  // Pages that require auth will redirect server-side.
});
