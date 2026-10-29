"""Local web dashboard for the scanner. Run with `vapt serve`."""
from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from flask import Flask, Response, abort, jsonify, request, send_from_directory

from .. import __version__
from ..checks import ALL
from ..report import to_html, to_json, to_markdown, to_sarif
from ..scanner import ScanConfig, ScanError, ScopeError, run_scan

LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
FORMATS = {
    "json": (to_json, "application/json", "report.json"),
    "md": (to_markdown, "text/markdown", "report.md"),
    "html": (to_html, "text/html", "report.html"),
    "sarif": (to_sarif, "application/sarif+json", "report.sarif"),
}


@dataclass
class Job:
    id: str
    target: str
    checks: list
    created: float = field(default_factory=time.time)
    status: str = "queued"  # queued | crawling | running | done | error
    current: Optional[str] = None
    completed: list = field(default_factory=list)
    log: list = field(default_factory=list)
    error: Optional[str] = None
    result: Optional[object] = None

    def brief(self) -> dict:
        d = {"id": self.id, "target": self.target, "status": self.status, "created": self.created}
        if self.result:
            d["summary"] = self.result.summary()
        return d

    def detail(self) -> dict:
        d = self.brief()
        d.update(checks=self.checks, current=self.current, completed=self.completed,
                 log=self.log[-200:], error=self.error)
        if self.result:
            d["result"] = self.result.to_dict()
        return d


def _int(body: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(body.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(f"'{key}' must be a number")
    return max(lo, min(hi, v))


def _config(body: dict) -> ScanConfig:
    target = str(body.get("target", "")).strip()
    if not target:
        raise ValueError("Enter a target URL")
    if "://" not in target:
        target = "http://" + target
    checks = body.get("checks") or None
    if checks is not None and not (isinstance(checks, list) and all(isinstance(c, str) for c in checks)):
        raise ValueError("'checks' must be a list of check names")
    try:
        delay = max(0.0, min(5.0, float(body.get("delay", 0))))
    except (TypeError, ValueError):
        raise ValueError("'delay' must be a number")
    cookie = str(body.get("cookie") or "").strip() or None
    return ScanConfig(
        target=target, authorized=bool(body.get("authorized")),
        max_pages=_int(body, "max_pages", 25, 1, 200), max_depth=_int(body, "max_depth", 2, 0, 6),
        max_requests=_int(body, "max_requests", 500, 10, 5000), delay=delay,
        test_post=bool(body.get("test_post")), verify_tls=not body.get("insecure"),
        cookie=cookie, checks=checks,
    )


def create_web_app(allow_any_host: bool = False) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    jobs: dict[str, Job] = {}
    lock = threading.Lock()

    @app.before_request
    def guard():
        # Blocks DNS-rebinding and cross-site requests from driving scans via the browser.
        if not allow_any_host and request.host.rsplit(":", 1)[0].lower() not in LOCAL_HOSTS:
            abort(403)
        if request.method == "POST" and not request.is_json:
            abort(415)

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'")
        return resp

    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(415)
    def err(e):
        return jsonify(error=e.description), e.code

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/meta")
    def meta():
        return jsonify(version=__version__, checks=[
            {"name": n, "description": (m.__doc__ or "").strip().splitlines()[0]} for n, m in ALL.items()])

    @app.get("/api/scans")
    def list_scans():
        with lock:
            items = sorted(jobs.values(), key=lambda j: -j.created)
            return jsonify([j.brief() for j in items][:30])

    @app.post("/api/scans")
    def start_scan():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="Send a JSON object"), 400
        try:
            cfg = _config(body)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        unknown = [c for c in (cfg.checks or []) if c not in ALL]
        if unknown:
            return jsonify(error=f"Unknown check(s): {', '.join(unknown)}"), 400
        job = Job(uuid.uuid4().hex[:10], cfg.target, cfg.checks or list(ALL))

        def log(msg: str):
            job.log.append(msg)
            m = re.match(r"\[\*\] Running check: (\w+)", msg)
            if m:
                if job.current:
                    job.completed.append(job.current)
                job.current, job.status = m.group(1), "running"
            elif msg.startswith("[*] Crawling"):
                job.status = "crawling"

        def work():
            try:
                job.result = run_scan(cfg, log=log)
                if job.current:
                    job.completed.append(job.current)
                job.current, job.status = None, "done"
            except (ScopeError, ScanError) as exc:
                job.error, job.status = str(exc), "error"
            except Exception as exc:  # keep the server alive on unexpected failures
                job.error, job.status = f"Unexpected error: {exc!r}", "error"

        with lock:
            jobs[job.id] = job
        threading.Thread(target=work, daemon=True).start()
        return jsonify(job.brief()), 202

    @app.get("/api/scans/<jid>")
    def get_scan(jid):
        job = jobs.get(jid)
        if not job:
            abort(404, "Scan not found")
        return jsonify(job.detail())

    @app.get("/api/scans/<jid>/report.<fmt>")
    def report(jid, fmt):
        job = jobs.get(jid)
        if not job or not job.result or fmt not in FORMATS:
            abort(404, "Report not available")
        fn, mime, name = FORMATS[fmt]
        return Response(fn(job.result), mimetype=mime,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    return app


def _start_lab(port: int = 5000):
    from werkzeug.serving import make_server

    from lab.app import create_app

    server = make_server("127.0.0.1", port, create_app(False), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"practice lab (intentionally vulnerable) on http://127.0.0.1:{port}  - scan this address")


def serve(host: str = "127.0.0.1", port: int = 8080, with_lab: bool = False) -> None:
    if with_lab:
        _start_lab()
    app = create_web_app(allow_any_host=host not in ("127.0.0.1", "localhost", "::1"))
    print(f"vapt dashboard on http://{host}:{port}  (Ctrl+C to stop)")
    app.run(host, port, debug=False, threaded=True)
