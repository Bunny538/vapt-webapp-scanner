"""HTTP method exposure via OPTIONS."""
from ..models import Finding

NAME = "methods"
RISKY = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}


def run(ctx):
    r = ctx.client.options(ctx.base)
    if r is None:
        return []
    allow = {m.strip().upper() for m in r.headers.get("Allow", "").split(",") if m.strip()}
    risky = sorted(allow & RISKY)
    if not risky:
        return []
    sev = "low"
    return [Finding(
        "VAPT-METH-001", "Risky HTTP methods enabled", sev, ctx.base,
        f"The server advertises {', '.join(risky)} on the site root. TRACE can aid cross-site tracing; "
        "PUT/DELETE may allow unintended modification if not access-controlled.",
        "Disable methods the application does not use at the web server / framework level.",
        evidence=f"Allow: {', '.join(sorted(allow))}", cwe="CWE-650",
        owasp="A05:2021 Security Misconfiguration")]
