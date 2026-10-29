"""Reflected XSS detection using a unique, inert marker tag (nothing is executed)."""
import secrets

from ..models import Finding
from ..utils import snippet

NAME = "xss"


def run(ctx):
    out = []
    for pt in ctx.testable_points():
        marker = "vx" + secrets.token_hex(3)
        needle = f"<{marker}>"
        r = ctx.send(pt, f'"><{marker}>')
        if r is None or 300 <= r.status_code < 400:
            continue
        if "html" in r.headers.get("Content-Type", "").lower() and needle in r.text:
            out.append(Finding(
                "VAPT-XSS-001", "Reflected cross-site scripting (XSS)", "high", pt.url,
                "User input is reflected into the HTML response without encoding, so injected markup "
                "is parsed by the browser. Attackers can run script in a victim's session.",
                "Contextually HTML-encode all output (use the template engine's auto-escaping), validate input, "
                "and deploy a strict Content-Security-Policy.",
                evidence=snippet(r.text, needle), parameter=pt.name,
                cwe="CWE-79", owasp="A03:2021 Injection"))
    return out
