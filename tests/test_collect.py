import json
import os
import stat

import httpx
import pytest
from omini_sdk import Config, PluginError
from omini_sdk.plugin import Plugin

from omini_synology.client import base_url
from omini_synology.collect import collect, uptime_s, wait_s
from omini_synology.collect import test as connection_test


def test_reads_the_nas(dsm, cfg):
    [d] = collect(cfg)
    assert d.key == "00:11:32:12:34:56"  # MAC of eth0, which has the URL's address
    assert d.name == "nas-office" and d.host == "192.168.1.30"
    assert d.role == "server" and d.vendor == "Synology"
    assert (d.model, d.serial) == ("DS920+", "2080PDN123456")
    assert d.os_version == "DSM 7.2.2-72806 Update 1"
    assert d.firmware.current == "7.2.2-72806 Update 1"
    assert d.firmware.update_available is None  # never asks Synology's servers
    assert d.uptime_s == 171 * 3600 + 57 * 60 + 22
    assert (d.cpu_count, d.cpu_pct, d.mem_pct) == (4, 9.0, 23.0)
    assert d.mem_total_bytes == 8192 * 1024 * 1024


def test_interfaces(dsm, cfg):
    [d] = collect(cfg)
    ports = {i.name: i for i in d.interfaces}
    assert list(ports) == ["eth0", "eth1", "pppoe"]
    eth0 = ports["eth0"]
    assert (eth0.type, eth0.mac, eth0.up, eth0.speed_mbps) == (
        "ethernet",
        "00:11:32:12:34:56",
        True,
        1000,
    )
    # IPv6 kept in its short form, link-local left out.
    assert eth0.ips == ["192.168.1.30/24", "2001:db8:1::30/64"]
    assert (ports["eth1"].up, ports["eth1"].speed_mbps, ports["eth1"].ips) == (False, None, None)
    assert d.ips == ["192.168.1.30", "2001:db8:1::30"]
    assert [m.root for m in d.macs] == ["00:11:32:12:34:56", "00:11:32:12:34:57"]
    assert [(g.name, g.address) for g in d.gateways] == [
        ("default gateway", "192.168.1.1"),
        ("default IPv6 gateway", "fe80::1"),  # a router's link-local: kept
    ]


def test_volumes_and_temperatures(dsm, cfg):
    [d] = collect(cfg)
    assert [(s.mount, s.fs_type, s.total_bytes, s.used_bytes) for s in d.storage] == [
        ("/volume1", "btrfs", 3830512730112, 1215752192000),
        ("/volume2", "ext4", 100000000000, 25000000000),
    ]
    assert [(t.sensor, t.kind, t.celsius) for t in d.temperatures] == [
        ("System", "board", 47),
        ("Drive 1", "disk", 35),
        ("Drive 2", "disk", 37),
    ]  # the M.2 drive reads 0: no reading, left out


def test_containers_are_services(dsm, cfg):
    [d] = collect(cfg)
    assert [(s.name, s.description, s.running) for s in d.services] == [
        ("backup-job", "restic/restic:0.17.1", False),
        ("plex", "plexinc/pms-docker:latest", True),
    ]


def test_without_container_manager(dsm, cfg):
    del dsm.routes["SYNO.Docker.Container__list"]
    [d] = collect(cfg)
    assert d.services is None
    assert connection_test(cfg).endswith(": 2 volumes")


def test_the_session_is_kept_for_the_next_run(dsm, cfg):
    collect(cfg)
    collect(cfg)
    assert dsm.logins == 1 and dsm.logouts == 0
    f = cfg.state_dir / "session.json"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    saved = f.read_text()
    assert cfg["password"] not in saved and "sid-1" in saved


def test_new_credentials_sign_in_again(dsm, cfg):
    collect(cfg)
    cfg["username"] = "other"
    with pytest.raises(PluginError, match="rejected the username or password"):
        collect(cfg)
    assert dsm.logins == 1  # the old session was not used for other credentials


def test_an_expired_session_signs_in_again(dsm, cfg):
    collect(cfg)
    dsm.sessions.clear()  # DSM timed the session out
    [d] = collect(cfg)
    assert d.name == "nas-office" and dsm.logins == 2


def test_without_a_state_folder_the_session_is_closed(dsm, cfg):
    collect(Config(dict(cfg), None))
    assert dsm.logins == 1 and dsm.logouts == 1 and not dsm.sessions


def test_the_connection_test_signs_out(dsm, cfg):
    msg = connection_test(cfg)
    assert (
        msg == "Connected to DS920+ (nas-office), DSM 7.2.2-72806 Update 1: 2 volumes, 2 containers"
    )
    assert dsm.logouts == 1 and not dsm.sessions
    assert not (cfg.state_dir / "session.json").exists()  # forgotten


def test_only_reads(dsm, cfg):
    collect(cfg)
    connection_test(cfg)
    posts = {(api, method) for m, _, api, method in dsm.calls if m == "POST"}
    assert posts == {("SYNO.API.Auth", "login")}  # the only POST: the sign-in
    methods = {method for _, _, _, method in dsm.calls}
    assert methods <= {"query", "login", "logout", "info", "get", "list", "load_info"}


def test_a_wrong_password_waits_before_signing_in_again(dsm, cfg):
    good, cfg["password"] = cfg["password"], "wrong"
    with pytest.raises(PluginError, match="rejected the username or password") as e:
        collect(cfg)
    assert "wrong" not in str(e.value)
    calls = len(dsm.calls)
    with pytest.raises(PluginError, match="waiting a few minutes"):
        collect(cfg)
    assert not any(m == "login" for *_, m in dsm.calls[calls:])  # DSM was not asked
    refused = cfg.state_dir / "login-refused.json"
    assert stat.S_IMODE(os.stat(refused).st_mode) == 0o600
    assert "wrong" not in refused.read_text()
    cfg["password"] = good  # new credentials are tried at once
    [d] = collect(cfg)
    assert d.name == "nas-office" and not refused.exists()  # a good sign-in clears it


def test_only_a_refused_password_waits(dsm, cfg):
    dsm.login_code = 407  # the address is blocked: not a wrong password
    with pytest.raises(PluginError, match="Allow/Block List"):
        collect(cfg)
    dsm.login_code = None
    [d] = collect(cfg)  # signed in at the next run
    assert d.name == "nas-office" and dsm.logins == 1


def test_two_step_verification_needs_another_account(dsm, cfg):
    dsm.login_code = 403
    with pytest.raises(PluginError, match="2-step verification"):
        connection_test(cfg)
    dsm.login_code = 406
    with pytest.raises(PluginError, match="enforces 2-step verification"):
        connection_test(cfg)


def test_a_blocked_address(dsm, cfg):
    dsm.login_code = 407
    with pytest.raises(PluginError, match="Allow/Block List"):
        collect(cfg)


def test_a_non_admin_account_reads_what_it_may(dsm, cfg):
    dsm.codes["SYNO.Storage.CGI.Storage"] = 105
    dsm.codes["SYNO.Docker.Container"] = 105
    [d] = collect(cfg)
    assert d.storage is None and d.services is None
    assert [t.sensor for t in d.temperatures] == ["System"]
    msg = connection_test(cfg)
    assert "The account may not read: containers, storage" in msg
    assert "administrators group" in msg


def test_system_information_is_essential(dsm, cfg):
    dsm.codes["SYNO.Core.System"] = 105
    with pytest.raises(PluginError, match="administrators group"):
        collect(cfg)


def test_http_errors(dsm, cfg):
    dsm.http_errors["/webapi/query.cgi"] = 403
    with pytest.raises(PluginError, match="HTTP 403"):
        connection_test(cfg)
    dsm.http_errors["/webapi/query.cgi"] = 401
    with pytest.raises(PluginError, match="HTTP 401"):
        connection_test(cfg)


def test_not_dsm(dsm, cfg):
    dsm.http_errors["/webapi/query.cgi"] = 404
    with pytest.raises(PluginError, match="no DSM Web API"):
        connection_test(cfg)


@pytest.fixture
def pauses(monkeypatch):
    out = []
    monkeypatch.setattr("time.sleep", out.append)
    return out


def test_a_timeout_is_an_error_the_user_can_read(dsm, cfg, pauses):
    dsm.http_errors["/webapi/entry.cgi"] = httpx.ReadTimeout("slow")
    with pytest.raises(PluginError, match="did not answer in time"):
        collect(cfg)
    assert pauses == []  # the sign-in is a POST: never sent again after a timeout


def test_an_optional_api_that_times_out_is_skipped(dsm, cfg, pauses, monkeypatch):
    """Like every plugin: optional data DSM does not answer in time is left
    out, the rest is reported."""
    handler = dsm.handler

    def slow_storage(request):
        if "SYNO.Storage.CGI.Storage" in str(request.url):
            raise httpx.ReadTimeout("slow", request=request)
        return handler(request)

    use(monkeypatch, slow_storage)
    [d] = collect(cfg)
    assert d.storage is None and d.interfaces and d.services
    assert pauses == [1.0]  # the read was asked once more


def test_a_busy_nas_is_asked_again(dsm, cfg, pauses, monkeypatch):
    busy = {"left": 1}

    def flaky(request):
        if busy["left"]:
            busy["left"] -= 1
            return httpx.Response(503)
        return dsm.handler(request)

    use(monkeypatch, flaky)
    [d] = collect(cfg)
    assert d.name == "nas-office" and pauses == [1.0]


def use(monkeypatch, handler):
    from functools import partial

    import omini_synology.collect as collect_module
    from omini_synology.client import Client

    monkeypatch.setattr(
        collect_module, "Client", partial(Client, transport=httpx.MockTransport(handler))
    )


def test_an_unknown_api_answer_is_skipped(dsm, cfg):
    dsm.codes["SYNO.Core.System.Utilization"] = 103  # no such method on this DSM
    [d] = collect(cfg)
    assert d.cpu_pct is None and d.mem_pct is None and d.storage
    assert "may not read" not in connection_test(cfg)


def test_without_the_management_interface_the_lowest_port_mac_is_the_key(dsm, cfg):
    cfg["url"] = "https://nas.lan:5001"
    dsm.routes["SYNO.Core.System__info__network"]["data"]["nif"] = [
        {**n, "addr": "", "ipv6": []}
        for n in dsm.routes["SYNO.Core.System__info__network"]["data"]["nif"]
    ]
    dsm.routes["SYNO.Core.Network.Interface__list"]["data"] = []
    [d] = collect(cfg)
    assert d.key == "00:11:32:12:34:56"


def test_without_interfaces_the_nas_is_keyed_by_its_serial(dsm, cfg):
    dsm.codes["SYNO.Core.Network.Interface"] = 105
    dsm.routes.pop("SYNO.Core.System__info__network")
    [d] = collect(cfg)
    assert d.key == "synology:2080PDN123456"  # never the server name (it can be edited)


def test_unreachable_host(cfg, pauses):
    cfg["url"] = "https://127.0.0.1:9"
    with pytest.raises(PluginError, match="cannot connect"):
        connection_test(cfg)
    assert pauses == [1.0, 2.0]


def test_required_fields(dsm, cfg):
    cfg["password"] = ""
    with pytest.raises(PluginError, match="required"):
        collect(cfg)


def test_addresses():
    assert base_url("192.168.1.30") == "https://192.168.1.30:5001"
    assert base_url("http://192.168.1.30") == "http://192.168.1.30:5000"
    assert base_url("https://nas.lan:443/webapi/") == "https://nas.lan:443"
    assert base_url("[fd00::30]") == "https://[fd00::30]:5001"


def test_an_ipv6_address(dsm, cfg):
    cfg["url"] = "https://[2001:db8:1::30]:5001"
    [d] = collect(cfg)
    assert d.host == "2001:db8:1::30" and d.key == "00:11:32:12:34:56"


def test_uptimes():
    assert uptime_s("0:05:09") == 309
    assert uptime_s("1234:00:00") == 1234 * 3600
    assert uptime_s("soon") is None and uptime_s(None) is None


def test_waits_as_long_as_asked(cfg):
    assert wait_s(cfg) == 15
    assert wait_s(Config({"timeout_s": 90}, None)) == 90
    assert wait_s(Config({"timeout_s": 1}, None)) == 5
    assert wait_s(Config({"timeout_s": 999}, None)) == 120


def test_the_sdk_accepts_the_device(dsm, cfg):
    import omini_synology.collect as collect_module

    p = Plugin()
    p.collect(collect_module.collect)
    request = json.dumps(
        {"protocol": 1, "action": "collect", "config": dict(cfg), "state_dir": str(cfg.state_dir)}
    )
    response, code = p.handle(request)
    assert code == 0 and len(response["devices"]) == 1


def test_manifest_is_read_only_and_groups_the_advanced_fields():
    from pathlib import Path

    manifest = (Path(__file__).parent.parent / "plugin.yaml").read_text()
    assert "\nchanges:" not in manifest and "\nbackup:" not in manifest
    fields = manifest.split("\nfields:", 1)[1].split("\n  - key: ")[1:]
    groups = {f.split("\n", 1)[0]: "group: Advanced" in f for f in fields}
    assert groups == {
        "url": False,
        "username": False,
        "password": False,
        "verify_tls": True,
        "timeout_s": True,
    }
