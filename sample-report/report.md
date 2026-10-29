# Vulnerability Assessment Report

- **Target:** http://127.0.0.1:5077
- **Started:** 2026-10-29T06:04:29+00:00  |  **Duration:** 0.03s
- **Pages crawled:** 7  |  **Parameters tested:** 6  |  **Requests:** 45

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 7 |
| Medium | 7 |
| Low | 7 |
| Info | 4 |

## Findings

### 1. [HIGH] CORS reflects arbitrary Origin with credentials

- **ID:** VAPT-CORS-REFLECT
- **URL:** http://127.0.0.1:5077
- **Classification:** CWE-942 / A05:2021 Security Misconfiguration

Any website can make authenticated cross-origin requests and read the responses.

**Evidence**

```
Origin: https://vapt-evil.example -> ACAO: https://vapt-evil.example, ACAC: True
```

**Remediation:** Validate Origin against an allow-list; never combine reflected origins with credentials.

### 2. [HIGH] Exposed backup file (backup.sql)

- **ID:** VAPT-PATH-BACKUP
- **URL:** http://127.0.0.1:5077/backup.sql
- **Classification:** CWE-530 / A05:2021 Security Misconfiguration

Database dumps expose all application data.

**Evidence**

```
HTTP 200, 55 bytes, Content-Type: application/octet-stream
```

**Remediation:** Delete backups from the web root.

### 3. [HIGH] Exposed .env file

- **ID:** VAPT-PATH-ENV
- **URL:** http://127.0.0.1:5077/.env
- **Classification:** CWE-538 / A05:2021 Security Misconfiguration

Environment files commonly hold database passwords and API keys.

**Evidence**

```
HTTP 200, 42 bytes, Content-Type: text/plain; charset=utf-8
```

**Remediation:** Remove the file from the web root, deny dotfiles, and rotate any exposed secrets.

### 4. [HIGH] Exposed .git repository

- **ID:** VAPT-PATH-GIT
- **URL:** http://127.0.0.1:5077/.git/HEAD
- **Classification:** CWE-538 / A05:2021 Security Misconfiguration

Source code and history can be downloaded, often including secrets.

**Evidence**

```
HTTP 200, 21 bytes, Content-Type: text/plain; charset=utf-8
```

**Remediation:** Block access to dotfiles/.git at the web server and never deploy the repository directory.

### 5. [HIGH] SQL injection (error-based)

- **ID:** VAPT-SQLI-001
- **URL:** http://127.0.0.1:5077/user
- **Parameter:** `id`
- **Classification:** CWE-89 / A03:2021 Injection

A single quote in the parameter triggered a database error, indicating user input is concatenated into a SQL query.

**Evidence**

```
id='1'' -> HTTP 500: sqlite3.OperationalError
```

**Remediation:** Use parameterised queries / prepared statements (never string concatenation), apply least-privilege database accounts, and return generic error messages.

### 6. [HIGH] Path traversal (arbitrary file read)

- **ID:** VAPT-TRAV-001
- **URL:** http://127.0.0.1:5077/download
- **Parameter:** `file`
- **Classification:** CWE-22 / A01:2021 Broken Access Control

A traversal sequence in the parameter returned the contents of a system file, so attackers can read files outside the intended directory.

**Evidence**

```
file=../../../../../../../../etc/passwd -> HTTP 200: root:x:0:0:
```

**Remediation:** Never build file paths from user input; map IDs to files server-side, or resolve the path and verify it stays inside an allowed base directory.

### 7. [HIGH] Reflected cross-site scripting (XSS)

- **ID:** VAPT-XSS-001
- **URL:** http://127.0.0.1:5077/search
- **Parameter:** `q`
- **Classification:** CWE-79 / A03:2021 Injection

User input is reflected into the HTML response without encoding, so injected markup is parsed by the browser. Attackers can run script in a victim's session.

**Evidence**

```
tml><html><head><title>VAPT Lab</title></head><body><h2>Results for "><vx0ab72a></h2></body></html>
```

**Remediation:** Contextually HTML-encode all output (use the template engine's auto-escaping), validate input, and deploy a strict Content-Security-Policy.

### 8. [MEDIUM] Cookie 'sessionid' missing HttpOnly

- **ID:** VAPT-CKIE-HTTPONLY
- **URL:** http://127.0.0.1:5077/
- **Parameter:** `sessionid`
- **Classification:** CWE-1004 / A05:2021 Security Misconfiguration

JavaScript can read this cookie, so any XSS flaw can steal it.

**Evidence**

```
sessionid=lab-session; Path=/
```

**Remediation:** Set the HttpOnly attribute on cookies that JavaScript does not need.

### 9. [MEDIUM] Directory listing enabled

- **ID:** VAPT-DISC-DIRLIST
- **URL:** http://127.0.0.1:5077/files/
- **Classification:** CWE-548 / A05:2021 Security Misconfiguration

Visitors can browse the directory contents, exposing files not meant to be public.

**Remediation:** Disable auto-indexing (e.g. `Options -Indexes`, `autoindex off`).

### 10. [MEDIUM] Stack trace / debug output exposed

- **ID:** VAPT-DISC-TRACE
- **URL:** http://127.0.0.1:5077/debug
- **Classification:** CWE-209 / A05:2021 Security Misconfiguration

Verbose errors reveal file paths, frameworks and logic useful for further attacks.

**Evidence**

```
Traceback (most recent call last)
```

**Remediation:** Disable debug mode and return generic error pages; log details server-side.

### 11. [MEDIUM] POST form without anti-CSRF token

- **ID:** VAPT-FORM-CSRF
- **URL:** http://127.0.0.1:5077/login
- **Classification:** CWE-352 / A01:2021 Broken Access Control

A state-changing form has no visible CSRF token; a malicious site may be able to submit it on behalf of a logged-in user (verify if SameSite cookies or other defences exist).

**Evidence**

```
Fields: username, password
```

**Remediation:** Add per-session CSRF tokens (or double-submit cookies) and validate them server-side.

### 12. [MEDIUM] Missing Content-Security-Policy

- **ID:** VAPT-HDR-CSP
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

No CSP is set, so the browser has no second line of defence against XSS and data injection.

**Remediation:** Add a restrictive policy, e.g. `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`.

### 13. [MEDIUM] Clickjacking protection missing

- **ID:** VAPT-HDR-XFO
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-1021 / A05:2021 Security Misconfiguration

Neither X-Frame-Options nor CSP frame-ancestors is set; the app can be framed by any site.

**Remediation:** Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.

### 14. [MEDIUM] Open redirect

- **ID:** VAPT-REDIR-001
- **URL:** http://127.0.0.1:5077/redirect
- **Parameter:** `next`
- **Classification:** CWE-601 / A01:2021 Broken Access Control

The application redirects to an attacker-supplied URL, enabling phishing via trusted links.

**Evidence**

```
next=https://vapt-evil.example/ -> HTTP 302 Location: https://vapt-evil.example/
```

**Remediation:** Only redirect to relative paths or an allow-list of hosts; reject `//` and absolute URLs.

### 15. [LOW] Cookie 'sessionid' missing SameSite

- **ID:** VAPT-CKIE-SAMESITE
- **URL:** http://127.0.0.1:5077/
- **Parameter:** `sessionid`
- **Classification:** CWE-1275 / A01:2021 Broken Access Control

Without SameSite the cookie is sent on cross-site requests, aiding CSRF.

**Evidence**

```
sessionid=lab-session; Path=/
```

**Remediation:** Set `SameSite=Lax` (or `Strict`).

### 16. [LOW] Sensitive HTML comment

- **ID:** VAPT-DISC-COMMENT
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-615 / A05:2021 Security Misconfiguration

Developer comments mentioning credentials/TODOs are visible to all users.

**Evidence**

```
TODO: remove admin password (admin/admin123) before release
```

**Remediation:** Strip comments from production HTML.

### 17. [LOW] X-Powered-By header discloses technology

- **ID:** VAPT-DISC-POWERED
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

The backing technology/version is advertised to every client.

**Evidence**

```
X-Powered-By: PHP/5.2.4
```

**Remediation:** Remove the X-Powered-By header.

### 18. [LOW] Server banner discloses version

- **ID:** VAPT-DISC-SERVER
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Exact software versions help attackers match known CVEs.

**Evidence**

```
Server: Werkzeug/3.1.9 Python/3.14.7, Apache/2.2.8 (Ubuntu)
```

**Remediation:** Suppress or genericise the Server header.

### 19. [LOW] Missing Referrer-Policy

- **ID:** VAPT-HDR-REFERRER
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Full URLs (possibly containing tokens or IDs) may leak to third parties via the Referer header.

**Remediation:** Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.

### 20. [LOW] Missing X-Content-Type-Options

- **ID:** VAPT-HDR-XCTO
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

Browsers may MIME-sniff responses and treat uploads/text as executable content.

**Remediation:** Send `X-Content-Type-Options: nosniff` on every response.

### 21. [LOW] Risky HTTP methods enabled

- **ID:** VAPT-METH-001
- **URL:** http://127.0.0.1:5077
- **Classification:** CWE-650 / A05:2021 Security Misconfiguration

The server advertises DELETE, PUT, TRACE on the site root. TRACE can aid cross-site tracing; PUT/DELETE may allow unintended modification if not access-controlled.

**Evidence**

```
Allow: DELETE, GET, HEAD, OPTIONS, PUT, TRACE
```

**Remediation:** Disable methods the application does not use at the web server / framework level.

### 22. [INFO] Password submitted over HTTP

- **ID:** VAPT-FORM-PASSWORD-HTTP
- **URL:** http://127.0.0.1:5077/login
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Credentials are sent unencrypted and can be sniffed on the network.

**Remediation:** Serve the whole site over HTTPS and redirect HTTP to HTTPS.

### 23. [INFO] Missing Permissions-Policy

- **ID:** VAPT-HDR-PERMS
- **URL:** http://127.0.0.1:5077/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

Powerful browser features (camera, geolocation, ...) are not explicitly restricted.

**Remediation:** Send a `Permissions-Policy` header disabling features the app does not use.

### 24. [INFO] robots.txt lists hidden paths

- **ID:** VAPT-PATH-ROBOTS
- **URL:** http://127.0.0.1:5077/robots.txt
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Disallowed paths are a roadmap of sensitive areas for an attacker; robots.txt is not access control.

**Evidence**

```
Disallow: /admin, /backup.sql
```

**Remediation:** Protect sensitive paths with authentication, not obscurity.

### 25. [INFO] Site not served over HTTPS

- **ID:** VAPT-TLS-NOHTTPS
- **URL:** http://127.0.0.1:5077
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Traffic is unencrypted and can be read or modified in transit.

**Remediation:** Enable HTTPS (e.g. Let's Encrypt) and redirect all HTTP traffic.


---
_Automated results require manual verification. Test only systems you are authorised to assess._