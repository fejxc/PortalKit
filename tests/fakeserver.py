"""本地假门户服务器：测试专用，全部路由显式注册，无真实网络/凭据。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

RouteFn = callable  # (portal, request_record, query) -> (status, headers, body)


class _Handler(BaseHTTPRequestHandler):
    server_version = "FakePortal/1.0"

    def log_message(self, *args):  # 静默
        pass

    def _dispatch(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        record = {
            "method": method,
            "path": parts.path,
            "raw": self.path,
            "body": body,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        self.server.portal.requests.append(record)
        route = self.server.portal.lookup(method, parts.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, payload = route(self.server.portal, record, query)
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload)
            headers = {**headers, "Content-Type": "application/json"}
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload.encode("utf-8"))

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def do_HEAD(self):  # noqa: N802
        self._dispatch("HEAD")


class FakePortalServer:
    """用法：portal.route("GET", "/path", fn)；fn(portal, rec, query)->(status, headers, body)。"""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._routes: dict[tuple[str, str], RouteFn] = {}
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.portal = self
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def route(self, method: str, path: str, fn: RouteFn) -> None:
        self._routes[(method, path)] = fn

    def lookup(self, method: str, path: str) -> RouteFn | None:
        return self._routes.get((method, path))

    def requests_to(self, path: str) -> list[dict]:
        return [r for r in self.requests if r["path"] == path]

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
