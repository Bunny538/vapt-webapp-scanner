"""Path traversal / local file inclusion detection using read-only canary files."""
import re

from ..models import Finding

NAME = "traversal"
PARAM = re.compile(r"^(file|filename|path|page|doc|document|template|include|folder|dir|download|name|view)$", re.I)
SIGNATURES = [
    (re.compile(r"root:[x*]:0:0:"), "../../../../../../../../etc/passwd"),
    (re.compile(r"^\[(fonts|extensions)\]", re.I | re.M), "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
]


def run(ctx):
    out = []
    for pt in ctx.testable_points():
        if not PARAM.match(pt.name):
            continue
        base = ctx.send(pt, pt.params.get(pt.name, ""))
        for sig, payload in SIGNATURES:
            r = ctx.send(pt, payload)
            if r is None or r.status_code >= 400:
                continue
            m = sig.search(r.text)
            if m and not (base is not None and sig.search(base.text)):
                out.append(Finding(
                    "VAPT-TRAV-001", "Path traversal (arbitrary file read)", "high", pt.url,
                    "A traversal sequence in the parameter returned the contents of a system file, so "
                    "attackers can read files outside the intended directory.",
                    "Never build file paths from user input; map IDs to files server-side, or resolve the path "
                    "and verify it stays inside an allowed base directory.",
                    evidence=f"{pt.name}={payload} -> HTTP {r.status_code}: {m.group(0)[:60]}",
                    parameter=pt.name, cwe="CWE-22", owasp="A01:2021 Broken Access Control"))
                break
    return out
