"""Static form analysis: CSRF tokens and credentials over HTTP (no submission)."""
import re

from ..models import Finding

NAME = "forms"
TOKEN = re.compile(r"csrf|xsrf|token|authenticity|nonce", re.I)


def run(ctx):
    out, seen = [], set()
    for page in ctx.pages:
        for form in page.forms:
            key = (form.action, form.method)
            if key in seen:
                continue
            seen.add(key)
            if form.method == "post" and not any(TOKEN.search(i["name"]) for i in form.inputs):
                out.append(Finding(
                    "VAPT-FORM-CSRF", "POST form without anti-CSRF token", "medium", form.action,
                    "A state-changing form has no visible CSRF token; a malicious site may be able to submit it "
                    "on behalf of a logged-in user (verify if SameSite cookies or other defences exist).",
                    "Add per-session CSRF tokens (or double-submit cookies) and validate them server-side.",
                    evidence=f"Fields: {', '.join(i['name'] for i in form.inputs)}",
                    cwe="CWE-352", owasp="A01:2021 Broken Access Control"))
            if any(i["type"] == "password" for i in form.inputs) and not form.action.startswith("https"):
                out.append(Finding(
                    "VAPT-FORM-PASSWORD-HTTP", "Password submitted over HTTP",
                    "info" if ctx.local else "high", form.action,
                    "Credentials are sent unencrypted and can be sniffed on the network.",
                    "Serve the whole site over HTTPS and redirect HTTP to HTTPS.",
                    cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))
    return out
