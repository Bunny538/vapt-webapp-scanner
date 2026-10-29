"""Information disclosure: banners, stack traces, directory listings, comments."""
import re

from ..models import Finding

NAME = "disclosure"
OWASP = "A05:2021 Security Misconfiguration"
TRACE = re.compile(r"Traceback \(most recent call last\)|Whitelabel Error Page|Stack trace:|"
                   r"at [\w.$]+\([\w.]+\.java:\d+\)|Fatal error:.*on line \d+", re.I)
COMMENT_KW = re.compile(r"password|passwd|secret|api[_-]?key|todo|fixme|credential|token", re.I)


def run(ctx):
    out = []
    home = ctx.home
    if home:
        server = home.headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            out.append(Finding(
                "VAPT-DISC-SERVER", "Server banner discloses version", "low", home.url,
                "Exact software versions help attackers match known CVEs.",
                "Suppress or genericise the Server header.", evidence=f"Server: {server}",
                cwe="CWE-200", owasp=OWASP))
        powered = home.headers.get("x-powered-by")
        if powered:
            out.append(Finding(
                "VAPT-DISC-POWERED", "X-Powered-By header discloses technology", "low", home.url,
                "The backing technology/version is advertised to every client.",
                "Remove the X-Powered-By header.", evidence=f"X-Powered-By: {powered}",
                cwe="CWE-200", owasp=OWASP))

    for page in ctx.pages:
        m = TRACE.search(page.text)
        if m:
            out.append(Finding(
                "VAPT-DISC-TRACE", "Stack trace / debug output exposed", "medium", page.url,
                "Verbose errors reveal file paths, frameworks and logic useful for further attacks.",
                "Disable debug mode and return generic error pages; log details server-side.",
                evidence=m.group(0)[:120], cwe="CWE-209", owasp=OWASP))
        if re.search(r"<title>\s*Index of /", page.text, re.I):
            out.append(Finding(
                "VAPT-DISC-DIRLIST", "Directory listing enabled", "medium", page.url,
                "Visitors can browse the directory contents, exposing files not meant to be public.",
                "Disable auto-indexing (e.g. `Options -Indexes`, `autoindex off`).",
                cwe="CWE-548", owasp=OWASP))
        for c in page.comments:
            if COMMENT_KW.search(c):
                out.append(Finding(
                    "VAPT-DISC-COMMENT", "Sensitive HTML comment", "low", page.url,
                    "Developer comments mentioning credentials/TODOs are visible to all users.",
                    "Strip comments from production HTML.", evidence=c[:120],
                    cwe="CWE-615", owasp=OWASP))
                break
    return out
