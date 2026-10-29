# Vulnerability Assessment Report

- **Target:** http://127.0.0.1:5000
- **Started:** 2026-10-29T06:27:34+00:00  |  **Duration:** 0.07s
- **Pages crawled:** 10  |  **Parameters tested:** 13  |  **Requests:** 102

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 10 |
| Medium | 9 |
| Low | 7 |
| Info | 6 |

## Findings

### 1. [HIGH] Authentication bypass via SQL injection

- **ID:** VAPT-AUTH-001
- **URL:** http://127.0.0.1:5000/UserLoginAction
- **Parameter:** `password`
- **Classification:** CWE-89 / A03:2021 Injection

A login with an unknown user and a always-true SQL condition in the password field was accepted, so the credential check is built by string concatenation.

**Evidence**

```
password="' OR '1'='1": baseline showed a failure message, injected request did not
```

**Remediation:** Use parameterised queries, store salted password hashes, and compare hashes in code, not in the SQL statement.

### 2. [HIGH] CORS reflects arbitrary Origin with credentials

- **ID:** VAPT-CORS-REFLECT
- **URL:** http://127.0.0.1:5000
- **Classification:** CWE-942 / A05:2021 Security Misconfiguration

Any website can make authenticated cross-origin requests and read the responses.

**Evidence**

```
Origin: https://vapt-evil.example -> ACAO: https://vapt-evil.example, ACAC: True
```

**Remediation:** Validate Origin against an allow-list; never combine reflected origins with credentials.

### 3. [HIGH] Exposed backup file (backup.sql)

- **ID:** VAPT-PATH-BACKUP
- **URL:** http://127.0.0.1:5000/backup.sql
- **Classification:** CWE-530 / A05:2021 Security Misconfiguration

Database dumps expose all application data.

**Evidence**

```
HTTP 200, 55 bytes, Content-Type: application/octet-stream
```

**Remediation:** Delete backups from the web root.

### 4. [HIGH] Exposed .env file

- **ID:** VAPT-PATH-ENV
- **URL:** http://127.0.0.1:5000/.env
- **Classification:** CWE-538 / A05:2021 Security Misconfiguration

Environment files commonly hold database passwords and API keys.

**Evidence**

```
HTTP 200, 42 bytes, Content-Type: text/plain; charset=utf-8
```

**Remediation:** Remove the file from the web root, deny dotfiles, and rotate any exposed secrets.

### 5. [HIGH] Exposed .git repository

- **ID:** VAPT-PATH-GIT
- **URL:** http://127.0.0.1:5000/.git/HEAD
- **Classification:** CWE-538 / A05:2021 Security Misconfiguration

Source code and history can be downloaded, often including secrets.

**Evidence**

```
HTTP 200, 21 bytes, Content-Type: text/plain; charset=utf-8
```

**Remediation:** Block access to dotfiles/.git at the web server and never deploy the repository directory.

### 6. [HIGH] SQL injection (error-based)

- **ID:** VAPT-SQLI-001
- **URL:** http://127.0.0.1:5000/UserLoginAction
- **Parameter:** `username`
- **Classification:** CWE-89 / A03:2021 Injection

A single quote in the parameter triggered a database error, indicating user input is concatenated into a SQL query.

**Evidence**

```
username='test'' -> HTTP 500: sqlite3.OperationalError
```

**Remediation:** Use parameterised queries / prepared statements (never string concatenation), apply least-privilege database accounts, and return generic error messages.

### 7. [HIGH] SQL injection (error-based)

- **ID:** VAPT-SQLI-001
- **URL:** http://127.0.0.1:5000/UserLoginAction
- **Parameter:** `password`
- **Classification:** CWE-89 / A03:2021 Injection

A single quote in the parameter triggered a database error, indicating user input is concatenated into a SQL query.

**Evidence**

```
password='test'' -> HTTP 500: sqlite3.OperationalError
```

**Remediation:** Use parameterised queries / prepared statements (never string concatenation), apply least-privilege database accounts, and return generic error messages.

### 8. [HIGH] SQL injection (error-based)

- **ID:** VAPT-SQLI-001
- **URL:** http://127.0.0.1:5000/user
- **Parameter:** `id`
- **Classification:** CWE-89 / A03:2021 Injection

A single quote in the parameter triggered a database error, indicating user input is concatenated into a SQL query.

**Evidence**

```
id='1'' -> HTTP 500: sqlite3.OperationalError
```

**Remediation:** Use parameterised queries / prepared statements (never string concatenation), apply least-privilege database accounts, and return generic error messages.

### 9. [HIGH] Path traversal (arbitrary file read)

- **ID:** VAPT-TRAV-001
- **URL:** http://127.0.0.1:5000/download
- **Parameter:** `file`
- **Classification:** CWE-22 / A01:2021 Broken Access Control

A traversal sequence in the parameter returned the contents of a system file, so attackers can read files outside the intended directory.

**Evidence**

```
file=../../../../../../../../etc/passwd -> HTTP 200: root:x:0:0:
```

**Remediation:** Never build file paths from user input; map IDs to files server-side, or resolve the path and verify it stays inside an allowed base directory.

### 10. [HIGH] Reflected cross-site scripting (XSS)

- **ID:** VAPT-XSS-001
- **URL:** http://127.0.0.1:5000/search
- **Parameter:** `q`
- **Classification:** CWE-79 / A03:2021 Injection

User input is reflected into the HTML response without encoding, so injected markup is parsed by the browser. Attackers can run script in a victim's session.

**Evidence**

```
tml><html><head><title>VAPT Lab</title></head><body><h2>Results for "><vxaf8d7e></h2></body></html>
```

**Remediation:** Contextually HTML-encode all output (use the template engine's auto-escaping), validate input, and deploy a strict Content-Security-Policy.

### 11. [MEDIUM] Cookie 'sessionid' missing HttpOnly

- **ID:** VAPT-CKIE-HTTPONLY
- **URL:** http://127.0.0.1:5000/
- **Parameter:** `sessionid`
- **Classification:** CWE-1004 / A05:2021 Security Misconfiguration

JavaScript can read this cookie, so any XSS flaw can steal it.

**Evidence**

```
sessionid=lab-session; Path=/
```

**Remediation:** Set the HttpOnly attribute on cookies that JavaScript does not need.

### 12. [MEDIUM] Directory listing enabled

- **ID:** VAPT-DISC-DIRLIST
- **URL:** http://127.0.0.1:5000/files/
- **Classification:** CWE-548 / A05:2021 Security Misconfiguration

Visitors can browse the directory contents, exposing files not meant to be public.

**Remediation:** Disable auto-indexing (e.g. `Options -Indexes`, `autoindex off`).

### 13. [MEDIUM] Stack trace / debug output exposed

- **ID:** VAPT-DISC-TRACE
- **URL:** http://127.0.0.1:5000/debug
- **Classification:** CWE-209 / A05:2021 Security Misconfiguration

Verbose errors reveal file paths, frameworks and logic useful for further attacks.

**Evidence**

```
Traceback (most recent call last)
```

**Remediation:** Disable debug mode and return generic error pages; log details server-side.

### 14. [MEDIUM] POST form without anti-CSRF token

- **ID:** VAPT-FORM-CSRF
- **URL:** http://127.0.0.1:5000/RegisterAction
- **Classification:** CWE-352 / A01:2021 Broken Access Control

A state-changing form has no visible CSRF token; a malicious site may be able to submit it on behalf of a logged-in user (verify if SameSite cookies or other defences exist).

**Evidence**

```
Fields: username, password, contact, email, address
```

**Remediation:** Add per-session CSRF tokens (or double-submit cookies) and validate them server-side.

### 15. [MEDIUM] POST form without anti-CSRF token

- **ID:** VAPT-FORM-CSRF
- **URL:** http://127.0.0.1:5000/UserLoginAction
- **Classification:** CWE-352 / A01:2021 Broken Access Control

A state-changing form has no visible CSRF token; a malicious site may be able to submit it on behalf of a logged-in user (verify if SameSite cookies or other defences exist).

**Evidence**

```
Fields: username, password
```

**Remediation:** Add per-session CSRF tokens (or double-submit cookies) and validate them server-side.

### 16. [MEDIUM] POST form without anti-CSRF token

- **ID:** VAPT-FORM-CSRF
- **URL:** http://127.0.0.1:5000/login
- **Classification:** CWE-352 / A01:2021 Broken Access Control

A state-changing form has no visible CSRF token; a malicious site may be able to submit it on behalf of a logged-in user (verify if SameSite cookies or other defences exist).

**Evidence**

```
Fields: username, password
```

**Remediation:** Add per-session CSRF tokens (or double-submit cookies) and validate them server-side.

### 17. [MEDIUM] Missing Content-Security-Policy

- **ID:** VAPT-HDR-CSP
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

No CSP is set, so the browser has no second line of defence against XSS and data injection.

**Remediation:** Add a restrictive policy, e.g. `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`.

### 18. [MEDIUM] Clickjacking protection missing

- **ID:** VAPT-HDR-XFO
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-1021 / A05:2021 Security Misconfiguration

Neither X-Frame-Options nor CSP frame-ancestors is set; the app can be framed by any site.

**Remediation:** Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.

### 19. [MEDIUM] Open redirect

- **ID:** VAPT-REDIR-001
- **URL:** http://127.0.0.1:5000/redirect
- **Parameter:** `next`
- **Classification:** CWE-601 / A01:2021 Broken Access Control

The application redirects to an attacker-supplied URL, enabling phishing via trusted links.

**Evidence**

```
next=https://vapt-evil.example/ -> HTTP 302 Location: https://vapt-evil.example/
```

**Remediation:** Only redirect to relative paths or an allow-list of hosts; reject `//` and absolute URLs.

### 20. [LOW] Cookie 'sessionid' missing SameSite

- **ID:** VAPT-CKIE-SAMESITE
- **URL:** http://127.0.0.1:5000/
- **Parameter:** `sessionid`
- **Classification:** CWE-1275 / A01:2021 Broken Access Control

Without SameSite the cookie is sent on cross-site requests, aiding CSRF.

**Evidence**

```
sessionid=lab-session; Path=/
```

**Remediation:** Set `SameSite=Lax` (or `Strict`).

### 21. [LOW] Sensitive HTML comment

- **ID:** VAPT-DISC-COMMENT
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-615 / A05:2021 Security Misconfiguration

Developer comments mentioning credentials/TODOs are visible to all users.

**Evidence**

```
TODO: remove admin password (admin/admin123) before release
```

**Remediation:** Strip comments from production HTML.

### 22. [LOW] X-Powered-By header discloses technology

- **ID:** VAPT-DISC-POWERED
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

The backing technology/version is advertised to every client.

**Evidence**

```
X-Powered-By: PHP/5.2.4
```

**Remediation:** Remove the X-Powered-By header.

### 23. [LOW] Server banner discloses version

- **ID:** VAPT-DISC-SERVER
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Exact software versions help attackers match known CVEs.

**Evidence**

```
Server: Werkzeug/3.1.9 Python/3.14.7, Apache/2.2.8 (Ubuntu)
```

**Remediation:** Suppress or genericise the Server header.

### 24. [LOW] Missing Referrer-Policy

- **ID:** VAPT-HDR-REFERRER
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Full URLs (possibly containing tokens or IDs) may leak to third parties via the Referer header.

**Remediation:** Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.

### 25. [LOW] Missing X-Content-Type-Options

- **ID:** VAPT-HDR-XCTO
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

Browsers may MIME-sniff responses and treat uploads/text as executable content.

**Remediation:** Send `X-Content-Type-Options: nosniff` on every response.

### 26. [LOW] Risky HTTP methods enabled

- **ID:** VAPT-METH-001
- **URL:** http://127.0.0.1:5000
- **Classification:** CWE-650 / A05:2021 Security Misconfiguration

The server advertises DELETE, PUT, TRACE on the site root. TRACE can aid cross-site tracing; PUT/DELETE may allow unintended modification if not access-controlled.

**Evidence**

```
Allow: DELETE, GET, HEAD, OPTIONS, PUT, TRACE
```

**Remediation:** Disable methods the application does not use at the web server / framework level.

### 27. [INFO] Password submitted over HTTP

- **ID:** VAPT-FORM-PASSWORD-HTTP
- **URL:** http://127.0.0.1:5000/RegisterAction
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Credentials are sent unencrypted and can be sniffed on the network.

**Remediation:** Serve the whole site over HTTPS and redirect HTTP to HTTPS.

### 28. [INFO] Password submitted over HTTP

- **ID:** VAPT-FORM-PASSWORD-HTTP
- **URL:** http://127.0.0.1:5000/UserLoginAction
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Credentials are sent unencrypted and can be sniffed on the network.

**Remediation:** Serve the whole site over HTTPS and redirect HTTP to HTTPS.

### 29. [INFO] Password submitted over HTTP

- **ID:** VAPT-FORM-PASSWORD-HTTP
- **URL:** http://127.0.0.1:5000/login
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Credentials are sent unencrypted and can be sniffed on the network.

**Remediation:** Serve the whole site over HTTPS and redirect HTTP to HTTPS.

### 30. [INFO] Missing Permissions-Policy

- **ID:** VAPT-HDR-PERMS
- **URL:** http://127.0.0.1:5000/
- **Classification:** CWE-693 / A05:2021 Security Misconfiguration

Powerful browser features (camera, geolocation, ...) are not explicitly restricted.

**Remediation:** Send a `Permissions-Policy` header disabling features the app does not use.

### 31. [INFO] robots.txt lists hidden paths

- **ID:** VAPT-PATH-ROBOTS
- **URL:** http://127.0.0.1:5000/robots.txt
- **Classification:** CWE-200 / A05:2021 Security Misconfiguration

Disallowed paths are a roadmap of sensitive areas for an attacker; robots.txt is not access control.

**Evidence**

```
Disallow: /admin, /backup.sql
```

**Remediation:** Protect sensitive paths with authentication, not obscurity.

### 32. [INFO] Site not served over HTTPS

- **ID:** VAPT-TLS-NOHTTPS
- **URL:** http://127.0.0.1:5000
- **Classification:** CWE-319 / A02:2021 Cryptographic Failures

Traffic is unencrypted and can be read or modified in transit.

**Remediation:** Enable HTTPS (e.g. Let's Encrypt) and redirect all HTTP traffic.


---
_Automated results require manual verification. Test only systems you are authorised to assess._