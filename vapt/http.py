"""HTTP client with rate limiting and a hard request budget."""
from __future__ import annotations

import time
from typing import Optional

import requests
import urllib3

UA = "vapt-scanner/1.0 (authorized security testing)"


class Client:
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.0,
        max_requests: int = 500,
        verify: bool = True,
        headers: Optional[dict] = None,
        cookie: Optional[str] = None,
    ):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        if headers:
            self.session.headers.update(headers)
        if cookie:
            self.session.headers["Cookie"] = cookie
        self.session.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.count = 0
        self.last_error: Optional[str] = None

    def request(self, method: str, url: str, **kw) -> Optional[requests.Response]:
        if self.count >= self.max_requests:
            self.last_error = "request budget exhausted"
            return None
        self.count += 1
        if self.delay:
            time.sleep(self.delay)
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.request(method, url, **kw)
        except requests.RequestException as exc:
            self.last_error = str(exc)
            return None

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw):
        return self.request("POST", url, **kw)

    def options(self, url: str, **kw):
        return self.request("OPTIONS", url, **kw)
