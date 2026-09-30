import threading
import time

import pytest

import api.server as server


@pytest.fixture(scope="session", autouse=True)
def api_server():
    httpd = server.ThreadingHTTPServer(
        ("127.0.0.1", 8081),
        server.APIHandler,
    )

    thread = threading.Thread(
        target=httpd.serve_forever,
        daemon=True,
    )
    thread.start()

    # Wait until the server is actually accepting connections.
    deadline = time.time() + 3

    while time.time() < deadline:
        try:
            import socket

            with socket.create_connection(
                ("127.0.0.1", 8081),
                timeout=0.2,
            ):
                break
        except OSError:
            time.sleep(0.05)
    else:
        httpd.shutdown()
        httpd.server_close()
        raise RuntimeError("API server failed to start")

    yield

    httpd.shutdown()
    thread.join(timeout=3)
    httpd.server_close()
