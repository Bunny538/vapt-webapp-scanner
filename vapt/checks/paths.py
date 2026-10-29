"""Exposed sensitive files and endpoints (content-validated to avoid soft-404 noise)."""
import re
import secrets

from ..models import Finding

NAME = "paths"
OWASP = "A05:2021 Security Misconfiguration"


def _not_html(r):
    return r.status_code == 200 and "text/html" not in r.headers.get("Content-Type", "").lower() and len(r.content) > 0


# (path, id, title, severity, validator, description, remediation, cwe)
PATHS = [
    ("/.git/HEAD", "VAPT-PATH-GIT", "Exposed .git repository", "high",
     lambda r: r.status_code == 200 and r.text.strip().startswith("ref:"),
     "Source code and history can be downloaded, often including secrets.",
     "Block access to dotfiles/.git at the web server and never deploy the repository directory.", "CWE-538"),
    ("/.env", "VAPT-PATH-ENV", "Exposed .env file", "high",
     lambda r: r.status_code == 200 and "<html" not in r.text[:300].lower() and bool(re.search(r"^[A-Z][A-Z0-9_]+=", r.text, re.M)),
     "Environment files commonly hold database passwords and API keys.",
     "Remove the file from the web root, deny dotfiles, and rotate any exposed secrets.", "CWE-538"),
    ("/backup.sql", "VAPT-PATH-BACKUP", "Exposed backup file (backup.sql)", "high", _not_html,
     "Database dumps expose all application data.", "Delete backups from the web root.", "CWE-530"),
    ("/backup.zip", "VAPT-PATH-BACKUP", "Exposed backup file (backup.zip)", "high", _not_html,
     "Archives may contain source code, configs and data.", "Delete backups from the web root.", "CWE-530"),
    ("/db.sqlite3", "VAPT-PATH-BACKUP", "Exposed database file (db.sqlite3)", "high", _not_html,
     "A raw database file is downloadable.", "Store data files outside the web root.", "CWE-530"),
    ("/phpinfo.php", "VAPT-PATH-PHPINFO", "phpinfo() page exposed", "medium",
     lambda r: r.status_code == 200 and "phpinfo()" in r.text,
     "Reveals configuration, paths and loaded modules.", "Remove the page.", "CWE-200"),
    ("/server-status", "VAPT-PATH-STATUS", "Apache server-status exposed", "medium",
     lambda r: r.status_code == 200 and "Apache Server Status" in r.text,
     "Leaks live request data and internal client IPs.", "Restrict to localhost / admin networks.", "CWE-200"),
    ("/actuator/env", "VAPT-PATH-ACTUATOR", "Spring Boot actuator /env exposed", "high",
     lambda r: r.status_code == 200 and "propertySources" in r.text,
     "Exposes environment properties, potentially secrets.", "Secure or disable actuator endpoints.", "CWE-200"),
    ("/.DS_Store", "VAPT-PATH-DSSTORE", ".DS_Store file exposed", "low",
     lambda r: r.status_code == 200 and r.content[:8] == b"\x00\x00\x00\x01Bud1",
     "Leaks directory structure and file names.", "Delete the file and block dotfiles.", "CWE-538"),
    ("/swagger.json", "VAPT-PATH-APIDOC", "API documentation exposed", "info",
     lambda r: r.status_code == 200 and ("swagger" in r.text[:500].lower() or "openapi" in r.text[:500].lower()),
     "Public API docs reveal the full attack surface.", "Restrict docs in production if not intended to be public.", "CWE-200"),
    ("/openapi.json", "VAPT-PATH-APIDOC", "API documentation exposed", "info",
     lambda r: r.status_code == 200 and "openapi" in r.text[:500].lower(),
     "Public API docs reveal the full attack surface.", "Restrict docs in production if not intended to be public.", "CWE-200"),
]


def run(ctx):
    out, reported = [], set()
    for path, fid, title, sev, valid, desc, rem, cwe in PATHS:
        r = ctx.client.get(ctx.base.rstrip("/") + path)
        if r is None or not valid(r):
            continue
        key = (fid, path)
        if key in reported:
            continue
        reported.add(key)
        out.append(Finding(fid, title, sev, r.url, desc, rem,
                           evidence=f"HTTP {r.status_code}, {len(r.content)} bytes, "
                                    f"Content-Type: {r.headers.get('Content-Type', '?')}",
                           cwe=cwe, owasp=OWASP))

    r = ctx.client.get(ctx.base.rstrip("/") + "/robots.txt")
    if r is not None and r.status_code == 200 and "text/html" not in r.headers.get("Content-Type", "").lower():
        dis = [l.split(":", 1)[1].strip() for l in r.text.splitlines() if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip() not in ("", "/")]
        if dis:
            out.append(Finding(
                "VAPT-PATH-ROBOTS", "robots.txt lists hidden paths", "info", r.url,
                "Disallowed paths are a roadmap of sensitive areas for an attacker; robots.txt is not access control.",
                "Protect sensitive paths with authentication, not obscurity.",
                evidence="Disallow: " + ", ".join(dis[:10]), cwe="CWE-200", owasp=OWASP))
    return out
