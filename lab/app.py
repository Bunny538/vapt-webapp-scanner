"""
VAPT Lab - a DELIBERATELY VULNERABLE demo web app.

Use it only as a local scan target. Never deploy it to a public server or an
untrusted network. `--hardened` runs a fixed version of the same app so you can
compare scanner output before/after remediation.
"""
from __future__ import annotations

import argparse
import html
import sqlite3

from flask import Flask, Response, make_response, redirect, request


def get_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    con.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [(1, "alice", "alice@lab.test"), (2, "bob", "bob@lab.test")],
    )
    return con


def create_app(hardened: bool = False) -> Flask:
    app = Flask(__name__)

    @app.after_request
    def add_headers(resp):
        if hardened:
            resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Permissions-Policy"] = "geolocation=(), camera=()"
            resp.headers["Server"] = "webserver"
        else:
            resp.headers["Server"] = "Apache/2.2.8 (Ubuntu)"
            resp.headers["X-Powered-By"] = "PHP/5.2.4"
            origin = request.headers.get("Origin")
            if origin:  # vulnerable: reflects any origin with credentials
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    def page(body: str) -> Response:
        return Response(f"<!doctype html><html><head><title>VAPT Lab</title></head><body>{body}</body></html>",
                        mimetype="text/html")

    @app.route("/", methods=["GET"] if hardened else ["GET", "PUT", "DELETE", "TRACE"])
    def home():
        token = '<input type="hidden" name="csrf_token" value="lab-token">' if hardened else ""
        extra = "" if hardened else (
            '<!-- TODO: remove admin password (admin/admin123) before release -->'
            '<li><a href="/files/">Files</a></li><li><a href="/debug">Debug</a></li>'
        )
        resp = make_response(page(
            "<h1>VAPT Lab</h1><ul>"
            '<li><a href="/search?q=hello">Search</a></li>'
            '<li><a href="/user?id=1">User profile</a></li>'
            '<li><a href="/redirect?next=/">Go</a></li>'
            '<li><a href="/download?file=report.txt">Download</a></li>'
            f"{extra}</ul>"
            f'<form method="post" action="/login">{token}'
            '<input name="username"><input name="password" type="password"><button>Login</button></form>'
        ))
        if hardened:
            resp.set_cookie("sessionid", "lab-session", httponly=True, samesite="Lax")
        else:
            resp.set_cookie("sessionid", "lab-session")
        return resp

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        return page(f"<h2>Results for {html.escape(q) if hardened else q}</h2>")

    @app.get("/user")
    def user():
        uid = request.args.get("id", "1")
        con = get_db()
        try:
            if hardened:
                row = con.execute("SELECT name, email FROM users WHERE id = ?", (uid,)).fetchone()
            else:
                row = con.execute(f"SELECT name, email FROM users WHERE id = '{uid}'").fetchone()
        except sqlite3.Error as exc:
            return Response(f"<pre>sqlite3.{type(exc).__name__}: {exc}</pre>", status=500, mimetype="text/html")
        if not row:
            return page("<p>User not found</p>")
        return page(f"<p>Name: {html.escape(row[0])}, Email: {html.escape(row[1])}</p>")

    # Simulated file store: no real filesystem access, so the lab is safe to run anywhere.
    docs = {"report.txt": "Quarterly report (lab sample)\n"}
    fake_fs = {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\nlab:x:1000:1000::/home/lab:/bin/sh\n"}

    @app.get("/download")
    def download():
        name = request.args.get("file", "report.txt")
        if hardened:
            body = docs.get(name)
        else:
            parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
            body = docs.get(name) or fake_fs.get("/".join(parts))
        if body is None:
            return Response("Not found", status=404, mimetype="text/plain")
        return Response(body, mimetype="text/plain")

    @app.post("/login")
    def login():
        return page("<p>Invalid credentials</p>"), 401

    @app.get("/redirect")
    def go():
        target = request.args.get("next", "/")
        if hardened and not (target.startswith("/") and not target.startswith("//")):
            target = "/"
        return redirect(target)

    if not hardened:
        @app.get("/.git/HEAD")
        def git_head():
            return Response("ref: refs/heads/main\n", mimetype="text/plain")

        @app.get("/.env")
        def env():
            return Response("SECRET_KEY=lab-secret\nDB_PASSWORD=hunter2\n", mimetype="text/plain")

        @app.get("/backup.sql")
        def backup():
            return Response("INSERT INTO users VALUES (1,'alice','alice@lab.test');\n",
                            mimetype="application/octet-stream")

        @app.get("/robots.txt")
        def robots():
            return Response("User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n", mimetype="text/plain")

        @app.get("/files/")
        def files():
            return page("<title>Index of /files</title><h1>Index of /files</h1><ul><li>report-2024.pdf</li></ul>")

        @app.get("/debug")
        def debug():
            return page('<pre>Traceback (most recent call last):\n  File "app.py", line 42, in view\n'
                        "ZeroDivisionError: division by zero</pre>")

    return app


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--hardened", action="store_true", help="run the fixed version of the app")
    a = ap.parse_args()
    if not a.hardened:
        print("WARNING: running an intentionally vulnerable app. Keep it on localhost / an isolated network.")
    create_app(a.hardened).run(a.host, a.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
