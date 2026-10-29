import time

import pytest

from vapt.web import create_web_app


@pytest.fixture()
def client():
    return create_web_app().test_client()


def _wait(client, jid):
    for _ in range(100):
        d = client.get(f"/api/scans/{jid}").get_json()
        if d["status"] in ("done", "error"):
            return d
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_index_and_meta(client):
    assert b"vapt" in client.get("/").data
    assert len(client.get("/api/meta").get_json()["checks"]) >= 12


def test_scan_roundtrip_and_reports(client, vuln_url):
    r = client.post("/api/scans", json={"target": vuln_url, "checks": ["xss", "sqli"]})
    assert r.status_code == 202
    d = _wait(client, r.get_json()["id"])
    assert d["status"] == "done"
    assert {f["id"] for f in d["result"]["findings"]} >= {"VAPT-XSS-001", "VAPT-SQLI-001"}
    for fmt in ("json", "md", "html", "sarif"):
        assert client.get(f"/api/scans/{d['id']}/report.{fmt}").status_code == 200


def test_scope_guard_reported_as_error(client):
    d = _wait(client, client.post("/api/scans", json={"target": "http://93.184.216.34"}).get_json()["id"])
    assert d["status"] == "error" and "authorized" in d["error"]


def test_rejects_bad_requests(client):
    assert client.post("/api/scans", json={"target": ""}).status_code == 400
    assert client.post("/api/scans", json={"target": "http://127.0.0.1", "checks": ["nope"]}).status_code == 400
    assert client.post("/api/scans", data="x", content_type="text/plain").status_code == 415
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403


def test_refused_connection_gives_actionable_message(client):
    d = _wait(client, client.post("/api/scans", json={"target": "http://127.0.0.1:1"}).get_json()["id"])
    assert d["status"] == "error" and "Start the target application" in d["error"]
