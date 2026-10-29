"""Cookie attribute checks."""
import re

from ..models import Finding

NAME = "cookies"
SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login", re.I)


def parse_set_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.lower()] = v or True
    return name, attrs


def run(ctx):
    out, seen = [], set()
    for page in ctx.pages:
        for raw in page.set_cookies:
            name, attrs = parse_set_cookie(raw)
            if name in seen:
                continue
            seen.add(name)
            sensitive = bool(SESSIONISH.search(name))
            if "httponly" not in attrs:
                out.append(Finding(
                    "VAPT-CKIE-HTTPONLY", f"Cookie '{name}' missing HttpOnly",
                    "medium" if sensitive else "low", page.url,
                    "JavaScript can read this cookie, so any XSS flaw can steal it.",
                    "Set the HttpOnly attribute on cookies that JavaScript does not need.",
                    evidence=raw, parameter=name, cwe="CWE-1004", owasp="A05:2021 Security Misconfiguration"))
            if page.url.startswith("https") and "secure" not in attrs:
                out.append(Finding(
                    "VAPT-CKIE-SECURE", f"Cookie '{name}' missing Secure",
                    "medium" if sensitive else "low", page.url,
                    "The cookie may be transmitted over plain HTTP.",
                    "Set the Secure attribute.", evidence=raw, parameter=name,
                    cwe="CWE-614", owasp="A02:2021 Cryptographic Failures"))
            if "samesite" not in attrs:
                out.append(Finding(
                    "VAPT-CKIE-SAMESITE", f"Cookie '{name}' missing SameSite",
                    "low", page.url,
                    "Without SameSite the cookie is sent on cross-site requests, aiding CSRF.",
                    "Set `SameSite=Lax` (or `Strict`).", evidence=raw, parameter=name,
                    cwe="CWE-1275", owasp="A01:2021 Broken Access Control"))
    return out
