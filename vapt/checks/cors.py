"""CORS misconfiguration check using a harmless foreign Origin."""
from ..models import Finding

NAME = "cors"
EVIL = "https://vapt-evil.example"


def run(ctx):
    r = ctx.client.get(ctx.base, headers={"Origin": EVIL})
    if r is None:
        return []
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    ev = f"Origin: {EVIL} -> ACAO: {acao}, ACAC: {acac}"
    owasp = "A05:2021 Security Misconfiguration"
    if acao == EVIL and acac:
        return [Finding(
            "VAPT-CORS-REFLECT", "CORS reflects arbitrary Origin with credentials", "high", ctx.base,
            "Any website can make authenticated cross-origin requests and read the responses.",
            "Validate Origin against an allow-list; never combine reflected origins with credentials.",
            evidence=ev, cwe="CWE-942", owasp=owasp)]
    if acao == EVIL:
        return [Finding(
            "VAPT-CORS-REFLECT-NOCRED", "CORS reflects arbitrary Origin", "medium", ctx.base,
            "Arbitrary origins can read responses; risky if any endpoint is sensitive.",
            "Restrict Access-Control-Allow-Origin to a fixed allow-list.",
            evidence=ev, cwe="CWE-942", owasp=owasp)]
    if acao == "*":
        return [Finding(
            "VAPT-CORS-WILDCARD", "CORS wildcard origin", "info", ctx.base,
            "Responses are readable by any origin (acceptable only for fully public data).",
            "Confirm that no authenticated or private data is served with `*`.",
            evidence=ev, cwe="CWE-942", owasp=owasp)]
    return []
