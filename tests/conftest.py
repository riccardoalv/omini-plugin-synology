import json
import threading
from functools import partial
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

import omini_synology.collect as collect_module
from omini_synology.client import Client

FIXTURES = Path(__file__).parent / "fixtures"
USER, PASSWORD = "omini", "c0rrect-h0rse-battery-staple"


class FakeDSM:
    """Answers like DSM 7.2, from the JSON files in fixtures/
    (`SYNO.Core.System__info.json` is api=SYNO.Core.System&method=info;
    `SYNO.Core.System__info__network.json` the same with type=network)."""

    def __init__(self):
        self.routes = {}
        for f in FIXTURES.glob("*.json"):
            self.routes[f.stem] = json.loads(f.read_text())
        self.codes = {}  # api → DSM error code
        self.http_errors = {}  # path → HTTP status, or an exception to raise
        self.login_code = None  # a refused sign-in: its DSM error code
        self.sessions = set()
        self.logins = 0
        self.logouts = 0
        self.calls = []
        self.lock = threading.Lock()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = {k: v[-1] for k, v in parse_qs(request.url.query.decode()).items()}
        if request.method == "POST":
            params.update({k: v[-1] for k, v in parse_qs(request.content.decode()).items()})
        with self.lock:
            self.calls.append((request.method, path, params.get("api"), params.get("method")))
        failure = self.http_errors.get(path)
        if isinstance(failure, Exception):
            raise failure
        if failure:
            return httpx.Response(failure, text="Forbidden")
        if path == "/webapi/query.cgi":
            return httpx.Response(200, json=self.routes["SYNO.API.Info__query"])
        if path != "/webapi/entry.cgi":
            return httpx.Response(404, text="Not Found")
        api, method = params.get("api"), params.get("method")
        if api == "SYNO.API.Auth":
            return self.auth(request, params)
        if params.get("_sid") not in self.sessions:
            return self.error(119)
        if api in self.codes:
            return self.error(self.codes[api])
        kind = params.get("type") if api == "SYNO.Core.System" else None
        key = f"{api}__{method}" + (f"__{kind}" if kind else "")
        if key not in self.routes:
            return self.error(102)
        return httpx.Response(200, json=self.routes[key])

    def auth(self, request, params):
        if params.get("method") == "login":
            assert request.method == "POST", "the password must not go in a URL"
            if self.login_code:
                return self.error(self.login_code)
            if params.get("account") != USER or params.get("passwd") != PASSWORD:
                return self.error(400)
            self.logins += 1
            sid = f"sid-{self.logins}"
            self.sessions.add(sid)
            return httpx.Response(200, json={"success": True, "data": {"sid": sid, "did": "x"}})
        if params.get("method") == "logout":
            self.logouts += 1
            self.sessions.discard(params.get("_sid"))
            return httpx.Response(200, json={"success": True})
        return self.error(103)

    @staticmethod
    def error(code):
        return httpx.Response(200, json={"success": False, "error": {"code": code}})


@pytest.fixture
def dsm(monkeypatch):
    fake = FakeDSM()
    monkeypatch.setattr(
        collect_module, "Client", partial(Client, transport=httpx.MockTransport(fake.handler))
    )
    return fake


@pytest.fixture
def cfg(tmp_path):
    from omini_sdk import Config

    return Config(
        {"url": "https://192.168.1.30:5001", "username": USER, "password": PASSWORD},
        tmp_path / "state",
    )
