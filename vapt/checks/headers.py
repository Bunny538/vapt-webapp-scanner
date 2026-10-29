"""Security response headers."""
import re

from ..models import Finding

NAME = "headers"

_MISSING = [
    ("content-security-policy", "VAPT-HDR-CSP", "Missing Content-Security-Policy", "medium",
     "No CSP is set, so the browser has no second line of defence against XSS and data injection.",
     "Add a restrictive policy, e.g. `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`.",
     "CWE-693"),
    ("x-content-type-options", "VAPT-HDR-XCTO", "Missing X-Content-Type-Options", "low",
     "Browsers may MIME-sniff responses and treat uploads/text as executable content.",
     "Send `X-Content-Type-Options: nosniff` on every response.", "CWE-693"),
    ("referrer-policy", "VAPT-HDR-REFERRER", "Missing Referrer-Policy", "low",
     "Full URLs (possibly containing tokens or IDs) may leak to third parties via the Referer header.",
     "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.", "CWE-200"),
    ("permissions-policy", "VAPT-HDR-PERMS", "Missing Permissions-Policy", "info",
     "Powerful browser features (camera, geolocation, ...) are not explicitly restricted.",
     "Send a `Permissions-Policy` header disabling features the app does not use.", "CWE-693"),
]


def run(ctx):
    home = ctx.home
    if not home:
        return []
    h, url = home.headers, home.url
    out = []
    for header, fid, title, sev, desc, rem, cwe in _MISSING:
        if header not in h:
            out.append(Finding(fid, title, sev, url, desc, rem, cwe=cwe, owasp="A05:2021 Security Misconfiguration"))

    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(Finding(
            "VAPT-HDR-XFO", "Clickjacking protection missing", "medium", url,
            "Neither X-Frame-Options nor CSP frame-ancestors is set; the app can be framed by any site.",
            "Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
            cwe="CWE-1021", owasp="A05:2021 Security Misconfiguration"))

    if ctx.base.startswith("https") and "strict-transport-security" not in h:
        out.append(Finding(
            "VAPT-HDR-HSTS", "Missing HTTP Strict-Transport-Security", "medium", url,
            "Browsers are not told to insist on HTTPS, enabling SSL-stripping downgrade attacks.",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))

    if csp and re.search(r"(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\s\*(\s|;|$))", csp):
        out.append(Finding(
            "VAPT-HDR-CSP-WEAK", "Weak Content-Security-Policy", "low", url,
            "The CSP allows unsafe-inline/unsafe-eval or wildcard script sources, reducing XSS protection.",
            "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes.",
            evidence=csp, cwe="CWE-693", owasp="A05:2021 Security Misconfiguration"))
    return out
