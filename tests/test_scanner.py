import json

import pytest

from vapt.models import SEVERITY_ORDER
from vapt.report import to_html, to_json, to_markdown, write_reports
from vapt.scanner import ScanConfig, ScanError, ScopeError, run_scan
from vapt.utils import is_local_host

EXPECTED_VULN = {
    "VAPT-XSS-001", "VAPT-SQLI-001", "VAPT-REDIR-001", "VAPT-CORS-REFLECT",
    "VAPT-HDR-CSP", "VAPT-HDR-XFO", "VAPT-HDR-XCTO",
    "VAPT-CKIE-HTTPONLY", "VAPT-CKIE-SAMESITE",
    "VAPT-DISC-SERVER", "VAPT-DISC-POWERED", "VAPT-DISC-DIRLIST", "VAPT-DISC-TRACE", "VAPT-DISC-COMMENT",
    "VAPT-PATH-GIT", "VAPT-PATH-ENV", "VAPT-PATH-BACKUP", "VAPT-PATH-ROBOTS",
    "VAPT-FORM-CSRF", "VAPT-METH-001",
}


@pytest.fixture(scope="module")
def vuln_result(vuln_url):
    return run_scan(ScanConfig(target=vuln_url))


def test_detects_expected_vulnerabilities(vuln_result):
    ids = {f.id for f in vuln_result.findings}
    missing = EXPECTED_VULN - ids
    assert not missing, f"scanner missed: {sorted(missing)}"
    assert not vuln_result.errors


def test_findings_have_evidence_and_remediation(vuln_result):
    for f in vuln_result.findings:
        assert f.remediation and f.description
    xss = next(f for f in vuln_result.findings if f.id == "VAPT-XSS-001")
    assert xss.parameter == "q" and "<vx" in xss.evidence
    sqli = next(f for f in vuln_result.findings if f.id == "VAPT-SQLI-001")
    assert sqli.parameter == "id"


def test_hardened_app_has_no_medium_or_higher(hardened_url):
    result = run_scan(ScanConfig(target=hardened_url))
    bad = [f for f in result.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["medium"]]
    assert not bad, [(f.id, f.url) for f in bad]
    assert not result.errors


def test_post_forms_not_fuzzed_by_default(vuln_url):
    result = run_scan(ScanConfig(target=vuln_url, checks=["xss", "sqli"]))
    assert all("/login" not in f.url for f in result.findings)


def test_request_budget_is_enforced(vuln_url):
    result = run_scan(ScanConfig(target=vuln_url, max_requests=5))
    assert result.requests <= 5


def test_scope_guard_blocks_public_hosts():
    with pytest.raises(ScopeError):
        run_scan(ScanConfig(target="http://93.184.216.34"))


def test_rejects_bad_target_and_unknown_check(vuln_url):
    with pytest.raises(ScanError):
        run_scan(ScanConfig(target="ftp://127.0.0.1"))
    with pytest.raises(ScanError):
        run_scan(ScanConfig(target=vuln_url, checks=["nope"]))


def test_is_local_host():
    assert is_local_host("127.0.0.1") and is_local_host("localhost") and is_local_host("10.1.2.3")
    assert not is_local_host("8.8.8.8") and not is_local_host(None)


def test_reports_render(vuln_result, tmp_path):
    assert json.loads(to_json(vuln_result))["summary"]["high"] >= 3
    assert "# Vulnerability Assessment Report" in to_markdown(vuln_result)
    doc = to_html(vuln_result)
    assert "<!doctype html>" in doc and "<vx" not in doc  # evidence must be HTML-escaped
    paths = write_reports(vuln_result, str(tmp_path), ["json", "md", "html"])
    assert all(p.exists() for p in paths)


def test_cli_exit_codes(vuln_url, hardened_url, tmp_path):
    from vapt.cli import main

    assert main(["scan", vuln_url, "--out", str(tmp_path / "a")]) == 1
    assert main(["scan", vuln_url, "--out", str(tmp_path / "b"), "--fail-on", "none"]) == 0
    assert main(["scan", hardened_url, "--out", str(tmp_path / "c")]) == 0
    assert main(["scan", "http://93.184.216.34", "--out", str(tmp_path / "d")]) == 2
