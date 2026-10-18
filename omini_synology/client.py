"""Minimal Synology DSM Web API client: signs in with SYNO.API.Auth, keeps the
session (sid) in the state folder, and calls APIs by name.

https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from omini_sdk import PluginError, log

# httpx logs every request's URL at INFO; a DSM URL carries the session id.
logging.getLogger("httpx").setLevel(logging.WARNING)

SESSION = "Omini"  # the session name DSM shows in its connection list

# Codes of every API (DSM Web API guide, "Common error codes").
NO_SUCH_API = {102, 103, 104}  # API, method or version does not exist
PERMISSION_DENIED = 105
SESSION_GONE = {106, 107, 119}  # timed out, interrupted by another login, sid not found

# Codes of SYNO.API.Auth login.
LOGIN_ERRORS = {
    400: "DSM rejected the username or password",
    401: "the DSM account is disabled",
    402: (
        "the DSM account may not sign in: allow it the DSM application "
        "(Control Panel → Application Privileges → DSM)"
    ),
    403: "the DSM account uses 2-step verification: Omini needs an account without it",
    404: "the DSM account uses 2-step verification: Omini needs an account without it",
    406: (
        "DSM enforces 2-step verification for this account: Omini needs an account "
        "without it (Control Panel → Security → Account → 2-factor authentication)"
    ),
    407: (
        "DSM blocked Omini's address after failed sign-ins "
        "(Control Panel → Security → Protection → Allow/Block List)"
    ),
    408: "the password of the DSM account expired: sign in once in DSM and change it",
    409: "the password of the DSM account expired: sign in once in DSM and change it",
    410: "DSM asks to change the password of the account: sign in once in DSM and change it",
}

# After DSM refuses the credentials, wait before signing in again: DSM blocks
# an address after repeated failed sign-ins (10 in 5 minutes by default).
LOGIN_BACKOFF_S = 10 * 60


class Forbidden(Exception):
    """The account may not use an API (code 105)."""


class NotFound(Exception):
    """The API, method or version does not exist on this DSM (a package that
    is not installed, such as Container Manager)."""


class Unavailable(Exception):
    """The API answered with another error code."""


def base_url(url: str) -> str:
    """'192.168.1.30' → 'https://192.168.1.30:5001'; http:// → port 5000."""
    url = url.strip().rstrip("/")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise PluginError("the address looks like https://192.168.1.30:5001")
    netloc = parts.netloc
    if parts.port is None:
        netloc = f"{netloc}:{5001 if parts.scheme == 'https' else 5000}"
    path = parts.path
    if path.endswith("/webapi"):
        path = path[: -len("/webapi")]
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def fingerprint(url: str, username: str, password: str) -> str:
    return hashlib.sha256(f"{url}\0{username}\0{password}".encode()).hexdigest()


class Client:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 15,
        state_dir: Path | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base = base_url(url)
        self.username = username
        self.password = password
        self.state_dir = state_dir
        self.fingerprint = fingerprint(self.base, username, password)
        self.http = httpx.Client(
            base_url=self.base + "/webapi",
            verify=verify_tls,
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "omini-plugin-synology"},
            transport=transport,
        )
        self.apis: dict[str, dict[str, Any]] | None = None
        saved = self._load()
        self.sid: str | None = saved.get("sid") if saved.get("for") == self.fingerprint else None
        self.logins = 0

    @property
    def host(self) -> str:
        return urlsplit(self.base).hostname or ""

    def close(self, logout: bool = False) -> None:
        """Ends the run. With logout, the session is closed on DSM too and
        forgotten (a connection test, or a run without a state folder)."""
        try:
            if logout and self.sid:
                self.logout()
        finally:
            self.http.close()

    # --- state ------------------------------------------------------------------

    def _state_file(self) -> Path | None:
        return self.state_dir / "session.json" if self.state_dir else None

    def _load(self) -> dict[str, Any]:
        f = self._state_file()
        try:
            return json.loads(f.read_text()) if f and f.exists() else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict[str, Any]) -> None:
        """Only the session id and a hash of the address and credentials are
        kept, readable by the owner only; never the password."""
        f = self._state_file()
        if not f:
            return
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(data, out)
            os.chmod(f, 0o600)
        except OSError:
            log.debug("could not save the session")

    # --- transport ----------------------------------------------------------------

    def _send(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.ConnectError as e:
            raise PluginError(f"cannot connect to {self.base}") from e
        except httpx.TimeoutException as e:
            raise PluginError(f"{self.base} did not answer in time") from e
        except httpx.HTTPError as e:
            raise PluginError(f"request to {self.base} failed ({type(e).__name__})") from e
        if r.status_code in (401, 403):
            raise PluginError(
                f"{self.base} refused the request (HTTP {r.status_code}): "
                "a reverse proxy or DSM's firewall in the way?"
            )
        if r.status_code == 404:
            raise PluginError(f"{self.base} has no DSM Web API (/webapi): is it the DSM address?")
        if r.status_code >= 400:
            raise PluginError(f"{self.base} answered HTTP {r.status_code}")
        try:
            body = r.json()
        except json.JSONDecodeError as e:
            raise PluginError(
                f"{self.base} did not answer with JSON: is it the DSM address?"
            ) from e
        if not isinstance(body, dict) or "success" not in body:
            raise PluginError(f"{self.base} does not look like DSM (no Web API answer)")
        return body

    def api(self, name: str) -> dict[str, Any]:
        """Path and versions of an API, from SYNO.API.Info (no session needed)."""
        if self.apis is None:
            body = self._send(
                "GET",
                "/query.cgi",
                params={"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "all"},
            )
            data = body.get("data") if body.get("success") else None
            if not isinstance(data, dict):
                raise PluginError(f"{self.base} does not look like DSM (no API list)")
            self.apis = data
        info = self.apis.get(name)
        if not isinstance(info, dict) or not info.get("path"):
            raise NotFound(name)
        return info

    def _version(self, name: str, wanted: int) -> tuple[str, int]:
        info = self.api(name)
        low, high = int(info.get("minVersion") or 1), int(info.get("maxVersion") or 1)
        return str(info["path"]), max(low, min(wanted, high))

    # --- session --------------------------------------------------------------------

    def login(self) -> None:
        saved = self._load()
        refused = saved.get("refused") or {}
        if (
            refused.get("for") == self.fingerprint
            and time.time() - refused.get("at", 0) < LOGIN_BACKOFF_S
        ):
            raise PluginError(
                f"{refused.get('error')} (waiting a few minutes before signing in again)"
            )
        path, version = self._version("SYNO.API.Auth", 6)
        # A POST, so the password never shows in a URL (DSM's logs, proxies).
        body = self._send(
            "POST",
            "/" + path,
            data={
                "api": "SYNO.API.Auth",
                "version": str(version),
                "method": "login",
                "account": self.username,
                "passwd": self.password,
                "session": SESSION,
                "format": "sid",
            },
        )
        sid = (body.get("data") or {}).get("sid") if body.get("success") else None
        if not sid:
            code = (body.get("error") or {}).get("code")
            message = LOGIN_ERRORS.get(code, f"DSM refused the sign-in (code {code})")
            if code in (400, 401, 407):  # retrying makes it worse: wait
                self._write(
                    {"refused": {"for": self.fingerprint, "at": time.time(), "error": message}}
                )
            raise PluginError(message)
        self.sid = str(sid)
        self.logins += 1
        self._write({"for": self.fingerprint, "sid": self.sid})

    def logout(self) -> None:
        try:
            path, version = self._version("SYNO.API.Auth", 6)
            self._send(
                "GET",
                "/" + path,
                params={
                    "api": "SYNO.API.Auth",
                    "version": str(version),
                    "method": "logout",
                    "session": SESSION,
                    "_sid": self.sid,
                },
            )
        except (PluginError, NotFound):
            log.info("could not sign out of DSM")
        self.sid = None
        if self._load().get("sid"):
            self._write({})

    def call(self, name: str, method: str, version: int = 1, **params: Any) -> Any:
        """Calls an API method with the session and returns its `data`. A
        session DSM forgot (timed out, signed out) is opened again, once."""
        path, v = self._version(name, version)
        for attempt in range(2):
            if not self.sid:
                self.login()
            query = {"api": name, "version": str(v), "method": method, **params, "_sid": self.sid}
            body = self._send("GET", "/" + path, params=query)
            if body.get("success"):
                return body.get("data")
            code = (body.get("error") or {}).get("code")
            if code in SESSION_GONE and attempt == 0:
                log.info("DSM session expired (code %s), signing in again", code)
                self.sid = None
                continue
            if code == PERMISSION_DENIED:
                raise Forbidden(name)
            if code in NO_SUCH_API:
                raise NotFound(name)
            raise Unavailable(f"{name} {method}: code {code}")
        raise PluginError("DSM keeps closing the session")
