"""Login-form SQL injection (authentication bypass). Needs --test-post; submits only a boolean-true string."""
import re
import secrets

from ..models import Finding

NAME = "authbypass"
FAILED = re.compile(r"fail|invalid|incorrect|wrong|denied|not (found|registered)", re.I)
PAYLOAD = "' OR '1'='1"


def _login_fields(form):
    users = [i["name"] for i in form.inputs if i["type"] in ("text", "email") and re.search(r"user|login|email|name", i["name"], re.I)]
    pws = [i["name"] for i in form.inputs if i["type"] == "password"]
    return (users[0], pws[0]) if users and pws else None


def run(ctx):
    if not ctx.test_post:
        return []
    out, seen = [], set()
    for page in ctx.pages:
        for form in page.forms:
            fields = _login_fields(form)
            if form.method != "post" or not fields or form.action in seen:
                continue
            seen.add(form.action)
            ucol, pcol = fields
            data = {i["name"]: i["value"] for i in form.inputs if i["type"] not in ("submit", "button")}
            junk = "vapt" + secrets.token_hex(3)
            base = ctx.client.post(form.action, data={**data, ucol: junk, pcol: junk}, allow_redirects=False)
            hit = ctx.client.post(form.action, data={**data, ucol: junk, pcol: PAYLOAD}, allow_redirects=False)
            if base is None or hit is None or not FAILED.search(base.text):
                continue
            if hit.status_code < 500 and not FAILED.search(hit.text) and hit.text != base.text:
                out.append(Finding(
                    "VAPT-AUTH-001", "Authentication bypass via SQL injection", "high", form.action,
                    "A login with an unknown user and a always-true SQL condition in the password field was "
                    "accepted, so the credential check is built by string concatenation.",
                    "Use parameterised queries, store salted password hashes, and compare hashes in code, "
                    "not in the SQL statement.",
                    evidence=f"{pcol}={PAYLOAD!r}: baseline showed a failure message, injected request did not",
                    parameter=pcol, cwe="CWE-89", owasp="A03:2021 Injection"))
    return out
