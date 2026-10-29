"""Scan orchestration."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

from .checks import ALL
from .crawler import build_points, crawl
from .http import Client
from .models import SEVERITY_ORDER, Context, ScanResult
from .utils import is_local_host


class ScopeError(Exception):
    """Target is not a local/lab host and --authorized was not given."""


class ScanError(Exception):
    pass


@dataclass
class ScanConfig:
    target: str
    authorized: bool = False
    max_pages: int = 25
    max_depth: int = 2
    delay: float = 0.0
    timeout: float = 10.0
    max_requests: int = 500
    test_post: bool = False
    verify_tls: bool = True
    headers: dict = field(default_factory=dict)
    cookie: Optional[str] = None
    checks: Optional[list[str]] = None
    max_points: int = 40


def run_scan(cfg: ScanConfig, log: Callable[[str], None] = lambda m: None) -> ScanResult:
    u = urlparse(cfg.target)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ScanError("Target must be a full http(s) URL, e.g. http://127.0.0.1:5000")
    local = is_local_host(u.hostname)
    if not local and not cfg.authorized:
        raise ScopeError(
            f"{u.hostname} is not a loopback/private host. Only scan systems you own or have written "
            "permission to test, then re-run with --authorized."
        )
    names = cfg.checks or list(ALL)
    unknown = [n for n in names if n not in ALL]
    if unknown:
        raise ScanError(f"Unknown check(s): {', '.join(unknown)}. Available: {', '.join(ALL)}")

    client = Client(cfg.timeout, cfg.delay, cfg.max_requests, cfg.verify_tls, cfg.headers, cfg.cookie)
    t0, started = time.time(), datetime.now(timezone.utc).isoformat(timespec="seconds")
    base = f"{u.scheme}://{u.netloc}"

    log(f"[*] Crawling {cfg.target}")
    pages = crawl(client, cfg.target, cfg.max_pages, cfg.max_depth)
    if not pages:
        raise ScanError(f"Target unreachable: {client.last_error}")
    points = build_points(pages, base)
    log(f"[*] {len(pages)} page(s), {len(points)} injectable parameter(s)")

    ctx = Context(base=base, client=client, pages=pages, points=points, local=local,
                  test_post=cfg.test_post, max_points=cfg.max_points)
    findings, errors = [], []
    for name in names:
        log(f"[*] Running check: {name}")
        try:
            findings.extend(ALL[name].run(ctx))
        except Exception as exc:  # one broken check must not abort the scan
            errors.append(f"{name}: {exc!r}")

    seen, unique = set(), []
    for f in findings:
        key = (f.id, f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.id, f.url))

    return ScanResult(
        target=cfg.target, started=started,
        finished=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration=round(time.time() - t0, 2), requests=client.count, pages=len(pages),
        points=len(points), checks_run=names, findings=unique, errors=errors,
    )
