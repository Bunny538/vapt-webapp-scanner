"""Same-origin crawler that discovers pages, forms and injectable parameters."""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from .models import Form, Page, Point

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".woff", ".woff2",
    ".ttf", ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".webp",
)
TEXT_INPUTS = {"text", "search", "email", "url", "tel", "textarea", "password", "select"}


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.comments: list[str] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {
                "action": a.get("action") or "",
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            itype = (a.get("type") or ("text" if tag == "input" else tag)).lower()
            self._form["inputs"].append(
                {"name": a["name"], "type": itype, "value": a.get("value") or ""}
            )

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_comment(self, data):
        self.comments.append(data.strip())


def _key(url: str) -> str:
    p = urlparse(url)
    names = ",".join(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))
    return f"{p.scheme}://{p.netloc}{p.path}?{names}"


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawl(client, start: str, max_pages: int = 25, max_depth: int = 2) -> list[Page]:
    queue = deque([(start, 0)])
    seen: set[str] = set()
    pages: list[Page] = []
    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        k = _key(url)
        if k in seen:
            continue
        seen.add(k)
        resp = client.get(url)
        if resp is None:
            continue
        cookies: list[str] = []
        for r in [*resp.history, resp]:
            try:
                cookies.extend(r.raw.headers.getlist("Set-Cookie"))
            except AttributeError:
                sc = r.headers.get("Set-Cookie")
                if sc:
                    cookies.append(sc)
        page = Page(
            url=resp.url,
            status=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            text=resp.text[:500_000],
            set_cookies=cookies,
        )
        if "html" in resp.headers.get("Content-Type", "").lower():
            parser = _Parser()
            try:
                parser.feed(page.text)
            except Exception:  # malformed HTML must never kill a scan
                pass
            page.comments = parser.comments
            for f in parser.forms:
                page.forms.append(
                    Form(
                        page_url=page.url,
                        action=urldefrag(urljoin(page.url, f["action"]))[0],
                        method=f["method"],
                        inputs=f["inputs"],
                    )
                )
            for href in parser.links:
                full = urldefrag(urljoin(page.url, href))[0]
                if not full.startswith(("http://", "https://")):
                    continue
                if full.lower().split("?")[0].endswith(STATIC_EXT):
                    continue
                page.links.append(full)
                if depth < max_depth and _same_origin(start, full):
                    queue.append((full, depth + 1))
        pages.append(page)
    return pages


def build_points(pages: list[Page], origin: str) -> list[Point]:
    points: list[Point] = []
    seen: set[tuple] = set()

    def add(url, method, params, name, source):
        key = (url, method, name)
        if key in seen:
            return
        seen.add(key)
        points.append(Point(url=url, method=method, params=dict(params), name=name, source=source))

    for page in pages:
        for link in page.links:
            p = urlparse(link)
            if not p.query or not _same_origin(origin, link):
                continue
            params = dict(parse_qsl(p.query, keep_blank_values=True))
            base = f"{p.scheme}://{p.netloc}{p.path}"
            for name in params:
                add(base, "GET", params, name, "link")
        for form in page.forms:
            if not _same_origin(origin, form.action):
                continue
            params = {}
            for i in form.inputs:
                if i["type"] in ("submit", "button", "image", "file", "reset"):
                    continue
                params[i["name"]] = i["value"] or ("test" if i["type"] in TEXT_INPUTS else "")
            method = "POST" if form.method == "post" else "GET"
            for i in form.inputs:
                if i["type"] in TEXT_INPUTS:
                    add(form.action, method, params, i["name"], "form")
    return points
