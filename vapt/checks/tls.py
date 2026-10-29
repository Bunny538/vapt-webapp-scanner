"""Transport security: HTTPS use, certificate validity/expiry, protocol version."""
import socket
import ssl
import time
from urllib.parse import urlparse

from ..models import Finding

NAME = "tls"
OWASP = "A02:2021 Cryptographic Failures"


def run(ctx):
    u = urlparse(ctx.base)
    if u.scheme != "https":
        return [Finding(
            "VAPT-TLS-NOHTTPS", "Site not served over HTTPS", "info" if ctx.local else "medium", ctx.base,
            "Traffic is unencrypted and can be read or modified in transit.",
            "Enable HTTPS (e.g. Let's Encrypt) and redirect all HTTP traffic.",
            cwe="CWE-319", owasp=OWASP)]
    host, port = u.hostname, u.port or 443
    try:
        sctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with sctx.wrap_socket(sock, server_hostname=host) as s:
                cert, version = s.getpeercert(), s.version()
    except ssl.SSLError as exc:
        return [Finding("VAPT-TLS-CERT", "TLS certificate validation failed", "medium", ctx.base,
                        "The certificate is invalid, expired, self-signed or mismatched.",
                        "Install a valid certificate from a trusted CA that matches the hostname.",
                        evidence=str(exc)[:200], cwe="CWE-295", owasp=OWASP)]
    except OSError:
        return []
    out = []
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding("VAPT-TLS-VERSION", f"Legacy protocol negotiated ({version})", "medium", ctx.base,
                           "Deprecated protocol versions have known weaknesses.",
                           "Allow only TLS 1.2 and 1.3.", cwe="CWE-326", owasp=OWASP))
    if cert and cert.get("notAfter"):
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
        if days < 30:
            out.append(Finding("VAPT-TLS-EXPIRY", "TLS certificate expires soon", "low", ctx.base,
                               f"Certificate expires in {int(days)} days.",
                               "Renew the certificate and automate renewal.", cwe="CWE-298", owasp=OWASP))
    return out
