# VulnLab

VulnLab is a **safe, non-exploitable** local web app that teaches common web security issues by **simulating** attack behavior in **Demo Mode**, and showing real defensive practices in **Secure Mode**.

It also includes a premium, hacker-style UI:

- Matrix-style animated background + grid
- Boot/loading overlay with typing effect (optional)
- Fake terminal panel with simulated logs (and safe server event stream)
- Threat level indicator (simulated)
- Interactive "Toolkit" cards + tool simulations
- Defense & Protection checklists + Challenge Mode quizzes

## Run

```powershell
cd "d:\VS projects imp\Login Page\sql-injection-lab"
node server.js
```

## Run (Dev / Auto-Reload)

Node 24+ supports watch mode:

```powershell
cd "d:\VS projects imp\Login Page\sql-injection-lab"
npm run dev
```

If PowerShell blocks `npm.ps1` on your machine, use:

```powershell
cd "d:\VS projects imp\Login Page\sql-injection-lab"
& "$env:ProgramFiles\nodejs\npm.cmd" run dev
```

Open:

- `http://localhost:3000`

Preloaded users:

- `admin / admin123`
- `user / password`
- `test / test123`

## Safe Simulation Tokens

To trigger learning simulations without using real exploit payload strings, you can use:

- `[[SIM_SQLI]]` (SQL injection simulation trigger)
- `[[SIM_XSS]]` (XSS simulation trigger)

## Modes

- **Demo Mode**
  - Detects common SQLi/XSS patterns
  - Logs warnings (e.g. “SQL Injection Attempt Detected”)
  - Shows “unsafe query examples” and simulated responses
  - Does **not** execute unsafe queries or run payloads
- **Secure Mode**
  - Uses prepared statements
  - Uses bcrypt (via `bcryptjs`) for password hashing
  - Blocks suspected XSS payloads in comments/bio
  - Enforces authorization checks (admin routes, profile access)

## Files

- `server.js` Express server + mode toggle + safe simulations
- `database.js` SQLite schema + seed users + seed comments
- `public/` frontend
  - `index.html`
  - `login.html`
  - `dashboard.html`
  - `admin.html`
  - `styles.css`
  - `app.js`
