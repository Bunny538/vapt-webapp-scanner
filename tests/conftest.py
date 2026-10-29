import threading

import pytest
from werkzeug.serving import make_server

from lab.app import create_app


def _serve(hardened: bool):
    server = make_server("127.0.0.1", 0, create_app(hardened), threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="session")
def vuln_url():
    server, url = _serve(False)
    yield url
    server.shutdown()


@pytest.fixture(scope="session")
def hardened_url():
    server, url = _serve(True)
    yield url
    server.shutdown()
