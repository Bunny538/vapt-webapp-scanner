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
import threading

from werkzeug.security import check_password_hash, generate_password_hash
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
            '<li><a href="/Register.html">Sign up</a></li><li><a href="/UserLogin.html">User login</a></li>'
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


    # ---- Account flow: signup, login, welcome (mirrors the project's demo screens) ----
    accounts = sqlite3.connect(":memory:", check_same_thread=False)
    accounts.execute("CREATE TABLE accounts (username TEXT, password TEXT, contact TEXT, email TEXT, address TEXT)")
    lock = threading.Lock()
    TITLE = "Vulnerability Assessment and Penetration Testing of Web Application"
    CSS = ("body{margin:0;background:#1259b8;font-family:Georgia,serif;color:#fff;text-align:center}"
           "nav a{color:#fff;margin:0 18px;font-size:14px}.card{background:#fff;color:#111;width:62%;margin:18px auto;padding:24px}"
           "h1{font-size:18px;font-weight:400;margin:26px 0 12px}td{text-align:left;padding:3px 8px;font-size:13px}"
           "h2{color:#6b1d1d;font-size:17px}.msg{font:13px Arial}")

    def site(body: str, logged_in: bool = False) -> Response:
        nav = '<nav><a href="/index.html">Logout</a></nav>' if logged_in else (
            '<nav><a href="/index.html">Home</a><a href="/UserLogin.html">User Login</a>'
            '<a href="/Register.html">New User Signup Here</a></nav>')
        return Response(f"<!doctype html><html><head><title>{TITLE}</title><style>{CSS}</style></head><body>"
                        f"<h1>{TITLE}</h1>{nav}<div class=\"card\">{body}</div></body></html>", mimetype="text/html")

    csrf = '<input type="hidden" name="csrf_token" value="lab-token">' if hardened else ""

    def check_csrf():
        return not hardened or request.form.get("csrf_token") == "lab-token"

    @app.get("/index.html")
    def index_html():
        return site("<h2>Welcome</h2><p>Sign up for an account, then log in.</p>")

    @app.get("/Register.html")
    def register_page(msg: str = ""):
        return site(f'<h2>New User Signup Page</h2><p class="msg">{msg}</p>'
                    f'<form method="post" action="/RegisterAction">{csrf}<table style="margin:auto">'
                    '<tr><td>User Name</td><td><input name="username"></td></tr>'
                    '<tr><td>Password</td><td><input name="password" type="password"></td></tr>'
                    '<tr><td>Contact No</td><td><input name="contact"></td></tr>'
                    '<tr><td>Email ID</td><td><input name="email"></td></tr>'
                    '<tr><td>Address</td><td><input name="address"></td></tr></table><button>Submit</button></form>')

    @app.post("/RegisterAction")
    def register_action():
        if not check_csrf():
            return Response("Forbidden", status=403)
        f = request.form
        pw = generate_password_hash(f.get("password", "")) if hardened else f.get("password", "")
        with lock:
            accounts.execute("INSERT INTO accounts VALUES (?,?,?,?,?)",
                             (f.get("username", ""), pw, f.get("contact", ""), f.get("email", ""), f.get("address", "")))
        return register_page("Signup process completed.")

    @app.get("/UserLogin.html")
    def login_page(msg: str = ""):
        return site(f'<h2>User Login Page</h2><p class="msg">{msg}</p>'
                    f'<form method="post" action="/UserLoginAction">{csrf}<table style="margin:auto">'
                    '<tr><td>Username</td><td><input name="username"></td></tr>'
                    '<tr><td>Password</td><td><input name="password" type="password"></td></tr></table>'
                    '<button>Login</button></form>')

    @app.post("/UserLoginAction")
    def login_action():
        if not check_csrf():
            return Response("Forbidden", status=403)
        user, pw = request.form.get("username", ""), request.form.get("password", "")
        with lock:
            try:
                if hardened:  # parameterised query + hashed password
                    row = accounts.execute("SELECT username, password FROM accounts WHERE username = ?", (user,)).fetchone()
                    row = row if row and check_password_hash(row[1], pw) else None
                else:  # VULNERABLE: user input concatenated into the SQL string (authentication bypass)
                    row = accounts.execute(
                        f"SELECT username FROM accounts WHERE username='{user}' AND password='{pw}'").fetchone()
            except sqlite3.Error as exc:
                return Response(f"<pre>sqlite3.{type(exc).__name__}: {exc}</pre>", status=500, mimetype="text/html")
        if not row:
            return login_page("login failed")
        name = html.escape(row[0]) if hardened else row[0]
        return site(f"<p class=\"msg\">welcome '{name}'<br>You have successfully logged to application</p>", logged_in=True)

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
