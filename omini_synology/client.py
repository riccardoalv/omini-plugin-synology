"""Synology DSM Web API client, on the SDK's HTTP client: signs in with
SYNO.API.Auth, keeps the session (sid) in the state folder (the SDK's
``Session``), waits 10 minutes after DSM refuses the password
(``LoginBackoff``), and calls APIs by name. DSM answers its errors as codes in
a 200; ``call`` turns them into the SDK's errors (105 → Forbidden, 102 to 104
→ NotFound).

https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx
from omini_sdk import PluginError, log
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import (
    Forbidden,
    HttpError,
    LoginBackoff,
    NotFound,
    Session,
    Unauthorized,
    Unavailable,
    normalize_url,
)

__all__ = ["Client", "Forbidden", "NotFound", "Unavailable", "base_url"]

# httpx logs every request's URL at INFO; a DSM URL carries the session id.
logging.getLogger("httpx").setLevel(logging.WARNING)

SESSION = "Omini"  # the session name DSM shows in its connection list

# Codes of every API (DSM Web API guide, "Common error codes").
NO_SUCH_API = {102, 103, 104}  # API, method or version does not exist
PERMISSION_DENIED = 105
SESSION_GONE = {106, 107, 119}  # timed out, interrupted by another login, sid not found

# Codes of SYNO.API.Auth login.
WRONG_PASSWORD = 400
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

# After DSM refuses the password, wait before signing in again: DSM blocks an
# address after repeated failed sign-ins (10 in 5 minutes by default).
LOGIN_BACKOFF_MIN = 10


def base_url(url: str) -> str:
    """'192.168.1.30' → 'https://192.168.1.30:5001'; http:// → port 5000."""
    try:
        return normalize_url(url, port={"https": 5001, "http": 5000}, strip=("/webapi",))
    except PluginError as e:
        raise PluginError("the address looks like https://192.168.1.30:5001") from e


class Client(HttpClient):
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
        super().__init__(
            base_url(url),
            name="DSM",
            api="/webapi",
            verify_tls=verify_tls,
            timeout=timeout,
            user_agent="omini-plugin-synology",
            transport=transport,
        )
        self.username = username
        self.password = password
        self.state_dir = state_dir
        self.session = Session(state_dir, self.base, username, password)
        self.backoff_login = LoginBackoff(
            state_dir, self.base, username, password, minutes=LOGIN_BACKOFF_MIN
        )
        self.apis: dict[str, dict[str, Any]] | None = None
        self.sid: str | None = self.session.load().get("sid")
        self.logins = 0

    def close(self, logout: bool = False) -> None:
        """Ends the run. With logout, the session is closed on DSM too and
        forgotten (a connection test, or a run without a state folder)."""
        try:
            if logout and self.sid:
                self.logout()
        finally:
            super().close()

    # --- transport ----------------------------------------------------------------

    def check(self, r: httpx.Response, method: str, path: str) -> None:
        """DSM itself answers 200 (its errors are codes in the answer): an
        HTTP error is something else in the way, or not DSM."""
        status = r.status_code
        where = {"status": status, "method": method, "resource": path}
        if status in (401, 403):
            message = (
                f"{self.base} refused the request (HTTP {status}): "
                "a reverse proxy or DSM's firewall in the way?"
            )
            raise Unauthorized(message, **where) if status == 401 else HttpError(message, **where)
        if status == 404:
            raise NotFound(
                f"{self.base} has no DSM Web API (/webapi): is it the DSM address?", **where
            )
        super().check(r, method, path)

    def dsm(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        """A Web API answer: {"success": ..., "data" or "error": ...}."""
        body = self.request(method, path, **kw)
        if not isinstance(body, dict) or "success" not in body:
            raise PluginError(f"{self.base} does not look like DSM (no Web API answer)")
        return body

    def api(self, name: str) -> dict[str, Any]:
        """Path and versions of an API, from SYNO.API.Info (no session needed)."""
        if self.apis is None:
            body = self.dsm(
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
            raise NotFound(f"DSM has no {name}", resource=name)
        return info

    def _version(self, name: str, wanted: int) -> tuple[str, int]:
        info = self.api(name)
        low, high = int(info.get("minVersion") or 1), int(info.get("maxVersion") or 1)
        return str(info["path"]), max(low, min(wanted, high))

    # --- session --------------------------------------------------------------------

    def login(self) -> None:
        self.backoff_login.check()
        path, version = self._version("SYNO.API.Auth", 6)
        # A POST, so the password never shows in a URL (DSM's logs, proxies).
        body = self.dsm(
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
            if code == WRONG_PASSWORD:  # trying again would get the address blocked: wait
                self.backoff_login.refused(message)
            raise PluginError(message)
        self.sid = str(sid)
        self.logins += 1
        self.backoff_login.clear()
        self.session.save({"sid": self.sid})

    def logout(self) -> None:
        try:
            path, version = self._version("SYNO.API.Auth", 6)
            self.dsm(
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
        except PluginError:
            log.info("could not sign out of DSM")
        self.sid = None
        self.session.clear()

    def call(self, name: str, method: str, version: int = 1, **params: Any) -> Any:
        """Calls an API method with the session and returns its `data`. A
        session DSM forgot (timed out, signed out) is opened again, once."""
        path, v = self._version(name, version)
        for attempt in range(2):
            if not self.sid:
                self.login()
            query = {"api": name, "version": str(v), "method": method, **params, "_sid": self.sid}
            body = self.dsm("GET", "/" + path, params=query)
            if body.get("success"):
                return body.get("data")
            code = (body.get("error") or {}).get("code")
            if code in SESSION_GONE and attempt == 0:
                log.info("DSM session expired (code %s), signing in again", code)
                self.sid = None
                continue
            where = {"method": method, "resource": name}
            if code == PERMISSION_DENIED:
                raise Forbidden(f"the DSM account may not use {name}", status=None, **where)
            if code in NO_SUCH_API:
                raise NotFound(f"DSM has no {name} {method} (code {code})", **where)
            raise Unavailable(f"{name} {method}: code {code}", **where)
        raise PluginError("DSM keeps closing the session")
