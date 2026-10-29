"""Open redirect detection on redirect-like parameters."""
import re
from urllib.parse import urlparse

from ..models import Finding

NAME = "redirect"
PARAM = re.compile(r"^(next|url|redirect|redirect_uri|redirect_url|return|returnurl|return_to|dest|destination|continue|target|goto|redir|callback)$", re.I)
EVIL_HOST = "vapt-evil.example"


def run(ctx):
    out = []
    for pt in ctx.testable_points():
        if not PARAM.match(pt.name):
            continue
        r = ctx.send(pt, f"https://{EVIL_HOST}/")
        if r is None or not (300 <= r.status_code < 400):
            continue
        loc = r.headers.get("Location", "")
        if urlparse(loc).netloc.lower() == EVIL_HOST:
            out.append(Finding(
                "VAPT-REDIR-001", "Open redirect", "medium", pt.url,
                "The application redirects to an attacker-supplied URL, enabling phishing via trusted links.",
                "Only redirect to relative paths or an allow-list of hosts; reject `//` and absolute URLs.",
                evidence=f"{pt.name}=https://{EVIL_HOST}/ -> HTTP {r.status_code} Location: {loc}",
                parameter=pt.name, cwe="CWE-601", owasp="A01:2021 Broken Access Control"))
    return out
