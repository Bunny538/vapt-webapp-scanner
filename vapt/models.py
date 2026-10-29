"""Shared data models for the scanner."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    url: str
    description: str
    remediation: str = ""
    evidence: str = ""
    parameter: str = ""
    cwe: str = ""
    owasp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)


@dataclass
class Point:
    """A single injectable parameter discovered during crawling."""

    url: str
    method: str
    params: dict
    name: str
    source: str = "link"


@dataclass
class Page:
    url: str
    status: int
    headers: dict
    text: str
    set_cookies: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)


@dataclass
class Context:
    base: str
    client: Any
    pages: list[Page]
    points: list[Point]
    local: bool
    test_post: bool = False
    max_points: int = 40

    @property
    def home(self) -> Optional[Page]:
        return self.pages[0] if self.pages else None

    def testable_points(self) -> list[Point]:
        pts = [p for p in self.points if p.method == "GET" or self.test_post]
        return pts[: self.max_points]

    def send(self, point: Point, value: str):
        """Send the request for `point` with `value` substituted. No redirects."""
        params = dict(point.params)
        params[point.name] = value
        if point.method == "GET":
            return self.client.get(point.url, params=params, allow_redirects=False)
        return self.client.post(point.url, data=params, allow_redirects=False)


@dataclass
class ScanResult:
    target: str
    started: str
    finished: str
    duration: float
    requests: int
    pages: int
    points: int
    checks_run: list[str]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def max_severity(self) -> int:
        return max((SEVERITY_ORDER[f.severity] for f in self.findings), default=-1)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary()
        return d
