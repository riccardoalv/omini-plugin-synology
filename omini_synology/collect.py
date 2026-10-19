"""Turns DSM Web API answers into one Omini device: the Synology NAS, with
its interfaces, volumes, temperatures and Container Manager's containers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any, TypeVar

from omini_sdk import (
    Config,
    Device,
    Firmware,
    Gateway,
    Interface,
    PluginError,
    Service,
    Storage,
    Temperature,
    log,
)
from omini_sdk import optional as sdk_optional
from omini_sdk.http import settings as http_settings

from omini_synology.client import Client, Forbidden, NotFound, Unavailable

T = TypeVar("T")

MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

ADMIN = "a member of the administrators group (see the plugin's README)"


def wait_s(cfg: Config) -> float:
    """How long to wait for each answer: the "timeout_s" field (the SDK's
    default, 15 s), kept within 5 to 120 s."""
    return float(min(max(http_settings(cfg)["timeout"], 5), 120))


def client_from(cfg: Config) -> Client:
    url, user, password = cfg.str("url"), cfg.str("username").strip(), cfg.str("password")
    if not url.strip() or not user or not password:
        raise PluginError("the address, username and password are required")
    return Client(
        url,
        user,
        password,
        state_dir=cfg.state_dir,
        **{**http_settings(cfg), "timeout": wait_s(cfg)},
    )


# --- parsing helpers -------------------------------------------------------


def mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().replace("-", ":")
    return v if MAC.match(v) and v != "00:00:00:00:00:00" else None


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def counter(value: Any) -> int | None:
    n = number(value)
    return int(n) if n is not None and n >= 0 else None


def percent(value: Any) -> float | None:
    n = number(value)
    return None if n is None else round(min(max(n, 0), 100), 1)


def address(ip: Any) -> str | None:
    """A usable address in its short form (IPv6 too), else None."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    try:
        a = ipaddress.ip_address(ip.strip().split("/")[0])
    except ValueError:
        return None
    if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast:
        return None
    return a.compressed


def prefix_of(mask: Any) -> int | None:
    """'255.255.255.0' → 24; 24 → 24."""
    if isinstance(mask, int) and not isinstance(mask, bool):
        return mask
    if isinstance(mask, str) and mask.strip():
        if mask.strip().isdigit():
            return int(mask.strip())
        try:
            return ipaddress.ip_network(f"0.0.0.0/{mask.strip()}").prefixlen
        except ValueError:
            return None
    return None


def uptime_s(value: Any) -> int | None:
    """'171:57:22' (hours:minutes:seconds) → seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return counter(value)
    m = re.match(r"^\s*(\d+):(\d{1,2}):(\d{1,2})\s*$", str(value or ""))
    if not m:
        return None
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def dsm_version(value: Any) -> str | None:
    """'DSM 7.2.1-69057 Update 5' → '7.2.1-69057 Update 5'."""
    if not isinstance(value, str) or not value.strip():
        return None
    return re.sub(r"^DSM\s+", "", value.strip())


def optional(what: str, missing: list[str], fn: Callable[[], T], default: T) -> T:
    """Optional data: an API the account may not use, a package that is not
    installed, or a DSM that does not answer it now, never fails the
    collection (the SDK's optional); a refused API goes in ``missing`` by
    its name."""
    return sdk_optional(what, fn, default, missing=missing)


# --- pieces ------------------------------------------------------------------


def interfaces(network: Any, links: Any) -> list[Interface]:
    """SYNO.Core.System info type=network (`nif`: MAC, IPv4, IPv6) joined to
    SYNO.Core.Network.Interface list (link status and speed) by name."""
    by_link = {
        str(row.get("ifname")): row
        for row in (links if isinstance(links, list) else [])
        if isinstance(row, dict) and row.get("ifname")
    }
    nifs = network.get("nif") if isinstance(network, dict) else None
    rows: dict[str, dict[str, Any]] = {}
    for nif in nifs or []:
        if isinstance(nif, dict) and nif.get("id"):
            rows[str(nif["id"])] = nif
    for name in by_link:
        rows.setdefault(name, {})
    out = []
    for name in sorted(rows):
        if name == "lo":
            continue
        nif, link = rows[name], by_link.get(name, {})
        ips = []
        for raw, mask in ((nif.get("addr"), nif.get("mask")), (link.get("ip"), link.get("mask"))):
            ip = address(raw)
            if ip:
                plen = prefix_of(mask)
                cidr = f"{ip}/{plen}" if plen is not None else ip
                if not any(c.split("/")[0] == ip for c in ips):
                    ips.append(cidr)
        for v6 in [*(nif.get("ipv6") or []), *(link.get("ipv6") or [])]:
            if not isinstance(v6, dict):
                continue
            ip = address(v6.get("addr") or v6.get("address"))
            if ip and not any(c.split("/")[0] == ip for c in ips):
                plen = counter(v6.get("prefix_len") or v6.get("prefix_length"))
                ips.append(f"{ip}/{plen}" if plen else ip)
        status = str(link.get("status") or "").lower()
        up = True if status == "connected" else False if status == "disconnected" else None
        speed = counter(link.get("speed")) if up else None
        kind = str(nif.get("type") or link.get("type") or "").lower()
        out.append(
            Interface(
                name=name,
                type=port_type(name, kind),
                mac=mac(nif.get("mac") or link.get("mac")),
                ips=sorted(ips, key=lambda c: ":" in c) or None,
                up=up,
                speed_mbps=speed if speed and speed > 0 else None,
            )
        )
    return out


def port_type(name: str, kind: str) -> str:
    if kind == "bond" or name.startswith(("bond", "ovs_bond")):
        return "lag"
    if name.startswith("eth"):
        return "ethernet"
    return "other"


def key_of(mgmt: Interface | None, ifaces: list[Interface], serial: str | None, host: str) -> str:
    """The MAC of the interface Omini reaches DSM on; else the lowest MAC of
    a physical port; else the serial; else the address of the form (never
    the server name, which can be edited)."""
    if mgmt and mgmt.mac:
        return mgmt.mac
    physical = sorted(i.mac for i in ifaces if i.type == "ethernet" and i.mac)
    if physical:
        return physical[0]
    return f"synology:{serial or host}"


def gateways(network: Any) -> list[Gateway]:
    out = []
    if not isinstance(network, dict):
        return out
    for key, label in (("gateway", "default gateway"), ("v6gateway", "default IPv6 gateway")):
        try:  # an IPv6 router is usually announced by its link-local address: kept
            ip = ipaddress.ip_address(str(network.get(key) or "").strip()).compressed
        except ValueError:
            continue
        out.append(Gateway(name=label, address=ip, status="unknown"))
    return out


def volumes(info: Any) -> list[Storage]:
    out = []
    rows = info.get("volumes") if isinstance(info, dict) else None
    for v in sorted(
        (r for r in rows or [] if isinstance(r, dict)),
        key=lambda r: str(r.get("vol_path") or r.get("id")),
    ):
        mount = v.get("vol_path") or v.get("id")
        if not mount:
            continue
        if str(v.get("status") or "normal") != "normal":
            log.warning("volume %s is %s", mount, v.get("status"))
        size = v.get("size") or {}
        out.append(
            Storage(
                mount=str(mount),
                fs_type=str(v.get("fs_type") or "") or None,
                total_bytes=counter(size.get("total")),
                used_bytes=counter(size.get("used")),
            )
        )
    return out


def disk_temperatures(info: Any) -> list[Temperature]:
    out = []
    rows = info.get("disks") if isinstance(info, dict) else None
    for d in sorted((r for r in rows or [] if isinstance(r, dict)), key=lambda r: str(r.get("id"))):
        name = d.get("name") or d.get("longName") or d.get("id")
        smart = str(d.get("smart_status") or "normal").lower()
        if smart not in ("normal", "", "unknown"):
            log.warning("disk %s: SMART status %s", name, smart)
        c = number(d.get("temp"))
        if name and c is not None and c > 0:  # 0 or -1: no reading
            out.append(Temperature(sensor=str(name), kind="disk", celsius=c))
    return out


def containers(data: Any) -> list[Service]:
    rows = data.get("containers") if isinstance(data, dict) else data
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        state = row.get("State") or {}
        running = row.get("status") == "running" or state.get("Running") is True
        out.append(
            Service(
                name=str(row["name"]),
                description=str(row.get("image") or "") or None,
                running=running,
            )
        )
    return sorted(out, key=lambda s: s.name)


# --- the NAS -------------------------------------------------------------------


def system_info(c: Client) -> dict[str, Any]:
    """Essential: without it there is nothing to report."""
    try:
        info = c.call("SYNO.Core.System", "info", 1)
    except Forbidden as e:
        raise PluginError(
            f"the DSM account may not read the system information: it needs to be {ADMIN}"
        ) from e
    except Unavailable as e:
        if e.status is None:  # out of reach, or no answer in time
            raise
        raise PluginError(f"DSM did not give its system information: {e}") from e
    except NotFound as e:
        raise PluginError(f"DSM did not give its system information: {e}") from e
    if not isinstance(info, dict):
        raise PluginError(f"{c.base} does not look like DSM (no system information)")
    return info


def nas_device(c: Client, missing: list[str]) -> Device:
    info = system_info(c)
    network = optional(
        "network", missing, lambda: c.call("SYNO.Core.System", "info", 1, type="network"), {}
    )
    general = optional("network", missing, lambda: c.call("SYNO.Core.Network", "get", 1), {}) or {}
    links = optional(
        "network", missing, lambda: c.call("SYNO.Core.Network.Interface", "list", 1), []
    )
    usage = (
        optional(
            "utilization", missing, lambda: c.call("SYNO.Core.System.Utilization", "get", 1), {}
        )
        or {}
    )
    storage = optional(
        "storage", missing, lambda: c.call("SYNO.Storage.CGI.Storage", "load_info", 1), {}
    )
    docker = optional(
        "containers",
        missing,
        lambda: c.call("SYNO.Docker.Container", "list", 1, limit="-1", offset="0", type="all"),
        None,
    )

    ifaces = interfaces(network, links)
    mgmt = next((i for i in ifaces if any(x.split("/")[0] == c.host for x in i.ips or [])), None)
    if mgmt is None:
        mgmt = next((i for i in ifaces if i.mac and i.ips), None)
    ips: list[str] = []
    for i in ifaces:
        ips += [x.split("/")[0] for x in i.ips or [] if x.split("/")[0] not in ips]
    ips.sort(key=lambda ip: ":" in ip)
    name = str(
        (general.get("server_name") if isinstance(general, dict) else None)
        or (network.get("hostname") if isinstance(network, dict) else None)
        or info.get("model")
        or c.host
    )
    serial = str(info.get("serial") or "").strip() or None
    version = dsm_version(info.get("firmware_ver"))
    cpu = usage.get("cpu") or {}
    loads = [number(cpu.get(k)) for k in ("user_load", "system_load", "other_load")]
    temps = []
    if number(info.get("sys_temp")) is not None:
        temps.append(
            Temperature(sensor="System", kind="board", celsius=number(info.get("sys_temp")))
        )
    temps += disk_temperatures(storage)
    gw_source = dict(network) if isinstance(network, dict) else {}
    if isinstance(general, dict):
        for k in ("gateway", "v6gateway"):
            gw_source.setdefault(k, general.get(k))
    ram_mb = counter(info.get("ram_size"))
    return Device(
        key=key_of(mgmt, ifaces, serial, c.host),
        name=name,
        host=c.host if address(c.host) else (ips[0] if ips else None),
        role="server",
        vendor="Synology",
        model=str(info.get("model") or "").strip() or None,
        serial=serial,
        os_version=f"DSM {version}" if version else None,
        uptime_s=uptime_s(info.get("up_time")),
        cpu_pct=percent(sum(x for x in loads if x is not None))
        if any(x is not None for x in loads)
        else None,
        cpu_count=counter(info.get("cpu_cores")) or None,
        mem_pct=percent((usage.get("memory") or {}).get("real_usage")),
        mem_total_bytes=ram_mb * 1024 * 1024 if ram_mb else None,
        temperatures=temps or None,
        storage=volumes(storage) or None,
        # Only the installed version: an update check makes DSM ask
        # Synology's servers, a check the plugin never starts.
        firmware=Firmware(current=version) if version else None,
        macs=sorted({i.mac for i in ifaces if i.mac}) or None,
        ips=ips or None,
        interfaces=ifaces or None,
        gateways=gateways(gw_source) or None,
        services=containers(docker) or None,
    )


# --- plugin entry points -------------------------------------------------------


def collect(cfg: Config) -> list[Device]:
    c = client_from(cfg)
    # The session is kept in the state folder for the next run (DSM logs and
    # may notify every sign-in); without a state folder it is closed.
    logout = c.state_dir is None
    try:
        missing: list[str] = []
        device = nas_device(c, missing)
        if missing:
            log.warning(
                "the account may not read: %s (it needs to be %s)",
                ", ".join(sorted(set(missing))),
                ADMIN,
            )
        return [device]
    finally:
        c.close(logout=logout)


def test(cfg: Config) -> str:
    """A connection test runs with a state folder of its own: its session is
    always closed."""
    c = client_from(cfg)
    try:
        missing: list[str] = []
        d = nas_device(c, missing)
        n_vol = len(d.storage or [])
        msg = (
            f"Connected to {d.model or 'Synology'} ({d.name}), {d.os_version or 'DSM'}: "
            f"{n_vol} volume{'s' if n_vol != 1 else ''}"
        )
        if d.services is not None:
            msg += f", {len(d.services)} container{'s' if len(d.services) != 1 else ''}"
        if missing:
            denied = ", ".join(sorted(set(missing)))
            msg += f". The account may not read: {denied} (it needs to be {ADMIN})"
        return msg
    finally:
        c.close(logout=True)
