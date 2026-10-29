"""Report writers: JSON, Markdown, self-contained HTML."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanResult

ORDER = ["critical", "high", "medium", "low", "info"]
COLORS = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#ea580c", "low": "#ca8a04", "info": "#2563eb"}


def to_json(r: ScanResult) -> str:
    return json.dumps(r.to_dict(), indent=2)


def to_markdown(r: ScanResult) -> str:
    s = r.summary()
    lines = [
        "# Vulnerability Assessment Report", "",
        f"- **Target:** {r.target}", f"- **Started:** {r.started}  |  **Duration:** {r.duration}s",
        f"- **Pages crawled:** {r.pages}  |  **Parameters tested:** {r.points}  |  **Requests:** {r.requests}", "",
        "## Summary", "", "| Severity | Count |", "|---|---|",
    ]
    lines += [f"| {sev.capitalize()} | {s[sev]} |" for sev in ORDER]
    lines += ["", "## Findings", ""]
    if not r.findings:
        lines.append("No findings.")
    for i, f in enumerate(r.findings, 1):
        lines += [f"### {i}. [{f.severity.upper()}] {f.title}", "",
                  f"- **ID:** {f.id}", f"- **URL:** {f.url}"]
        if f.parameter:
            lines.append(f"- **Parameter:** `{f.parameter}`")
        if f.cwe or f.owasp:
            lines.append(f"- **Classification:** {f.cwe} {('/ ' + f.owasp) if f.owasp else ''}".rstrip())
        lines += ["", f.description, ""]
        if f.evidence:
            lines += ["**Evidence**", "", "```", f.evidence, "```", ""]
        lines += [f"**Remediation:** {f.remediation}", ""]
    if r.errors:
        lines += ["## Scan errors", ""] + [f"- {e}" for e in r.errors]
    lines += ["", "---", "_Automated results require manual verification. Test only systems you are authorised to assess._"]
    return "\n".join(lines)


_CSS = """
body{font-family:system-ui,sans-serif;margin:0;background:#f8fafc;color:#0f172a}
main{max-width:960px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px}.meta{color:#475569;font-size:14px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}
.card{flex:1;min-width:110px;background:#fff;border-radius:10px;padding:14px;border:1px solid #e2e8f0;text-align:center}
.card b{display:block;font-size:28px}
.f{background:#fff;border:1px solid #e2e8f0;border-left-width:6px;border-radius:8px;padding:16px;margin:14px 0}
.badge{color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;text-transform:uppercase}
.f h3{margin:8px 0}.k{color:#475569;font-size:13px}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}
footer{color:#64748b;font-size:12px;margin-top:32px}
"""


def to_html(r: ScanResult) -> str:
    e = html.escape
    s = r.summary()
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {COLORS[sev]}"><b>{s[sev]}</b>{sev.capitalize()}</div>'
        for sev in ORDER
    )
    body = []
    for i, f in enumerate(r.findings, 1):
        c = COLORS[f.severity]
        param = f'<div class="k">Parameter: <code>{e(f.parameter)}</code></div>' if f.parameter else ""
        cls = e(" / ".join(x for x in (f.cwe, f.owasp) if x))
        ev = f"<pre>{e(f.evidence)}</pre>" if f.evidence else ""
        body.append(
            f'<div class="f" style="border-left-color:{c}"><span class="badge" style="background:{c}">{e(f.severity)}</span>'
            f"<h3>{i}. {e(f.title)}</h3><div class=\"k\">{e(f.id)} &middot; {e(f.url)}</div>{param}"
            f'<div class="k">{cls}</div><p>{e(f.description)}</p>{ev}<p><b>Remediation:</b> {e(f.remediation)}</p></div>'
        )
    if not body:
        body.append("<p>No findings.</p>")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>VAPT Report - {e(r.target)}</title><style>{_CSS}</style></head><body><main>"
        f'<h1>Vulnerability Assessment Report</h1><div class="meta">Target: {e(r.target)} &middot; {e(r.started)} &middot; '
        f"{r.duration}s &middot; {r.pages} pages &middot; {r.points} parameters &middot; {r.requests} requests</div>"
        f'<div class="cards">{cards}</div>{"".join(body)}'
        "<footer>Automated results require manual verification. Test only systems you are authorised to assess.</footer>"
        "</main></body></html>"
    )


def write_reports(r: ScanResult, out_dir: str, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    writers = {"json": ("report.json", to_json), "md": ("report.md", to_markdown), "html": ("report.html", to_html)}
    paths = []
    for fmt in formats:
        if fmt not in writers:
            raise ValueError(f"Unknown format: {fmt}")
        name, fn = writers[fmt]
        p = out / name
        p.write_text(fn(r), encoding="utf-8")
        paths.append(p)
    return paths
