# omini-plugin-synology

[Omini](https://github.com/riccardoalv/omini) plugin for **Synology NAS**, through the **DSM Web API** with a dedicated account. It reports the NAS as one device, with its interfaces, volumes, temperatures and the containers of Container Manager.

It signs in with a `POST` (so the password never appears in a URL) and reads with `GET` requests only. It never starts an update check, a SMART test, a scrub or anything else.

Needs **Omini 1.7 or later** (it uses the HTTP client, login state, optional reads and errors of the plugin SDK that ships with it).

> **Experimental.** This plugin was built from Synology's Web API guides and the requests DSM's own web interface makes, and tested against answers shaped like them, not on a real Synology NAS yet. Reports from real systems are welcome.

## What it reads

| Data | Used for |
|---|---|
| Model, serial, DSM version, CPU cores, installed memory, uptime, system temperature | The NAS device and its health |
| CPU use (user + system + other) and memory use | Health |
| Network interfaces: MAC, IPv4 and IPv6 addresses, link status and speed; server name; default gateways (IPv4 and IPv6) | Ports of the NAS |
| Volumes: mount (`/volume1`), file system, size and used | Storage |
| Disks: temperature | Temperatures, kind `disk` (sensor: the drive's name, "Drive 1") |
| Container Manager (or the older Docker package): containers, image, running | Services |
| The installed version | Firmware (current only) |

The NAS is keyed by the MAC of the interface that has the address Omini connects to, else the lowest MAC of a physical port, else `synology:<serial>` (never the server name, which can be edited), else `synology:<address>`.

IPv6 is first-class: global and ULA IPv6 addresses are reported next to IPv4, in their short form; link-local addresses stay out, except the IPv6 default gateway's (an IPv6 router announces itself by its link-local address).

## Install

**Integrations → Add → Synology DSM** (when it is in Omini's plugin catalog), or install it from its address, `https://github.com/riccardoalv/omini-plugin-synology`.

## The account

DSM has no read-only role for its Web API. Use a **dedicated account** for Omini, so its sessions and sign-ins are easy to tell apart (DSM shows them under the session name `Omini`):

1. **Control Panel → User & Group → Create**: user `omini`, a long random password, **no 2-step verification** (see below).
2. Try it as a **regular user** first (not in `administrators`). **Control Panel → Application Privileges → DSM**: allow `omini` (without it DSM refuses the sign-in, code 402). Deny it every other application (File Station, SMB, AFP, …): it needs none, and give it no shared folder permissions.
3. **Test connection** in Omini lists what DSM refuses to that account (code 105, *permission denied*). On many DSM versions the system, storage and container APIs answer only to members of the **administrators** group; if the test says so, add `omini` to `administrators`, keep every application denied except DSM, and limit where it can sign in from (**Control Panel → Security → Firewall**, or **Account → Allow/Block list**). The plugin only reads, whatever the account may do.

### 2-step verification

The plugin cannot answer a one-time code: **the account must not use 2-step verification**. If DSM enforces it (**Control Panel → Security → Account → 2-factor authentication → Enforce 2-factor authentication for … administrator group / all users**), exclude the `omini` account, or the sign-in fails (codes 403, 404, 406) and Omini says so.

### Sessions

The plugin signs in once and keeps the session id (and only that, with a hash of the address and credentials, readable by its owner only, `0600`) in its state folder (`session.json`), so the next collections reuse it instead of signing in every minute (every sign-in is logged by DSM and may send a "new sign-in" notification). A session DSM closed (timed out, signed out) is opened again, once. A connection test, which runs with a state folder of its own, and a run without a state folder **sign out** at the end. Changing the address, username or password opens a new session.

After DSM rejects the username or password (code 400), the plugin waits 10 minutes before signing in again (kept in `login-refused.json`, cleared by a good sign-in; other credentials are tried at once): DSM blocks an address after repeated failed sign-ins (**Control Panel → Security → Protection**, 10 in 5 minutes by default). Other refusals (a disabled account, a blocked address, 2-step verification) are tried again at the next run.

## Form fields

| Field | Example | Notes |
|---|---|---|
| Address | `https://192.168.1.30:5001` | Port 5001 for `https://` when none is given, 5000 for `http://` (prefer HTTPS: the password is sent at every sign-in). IPv6: `https://[fd00::30]:5001` |
| Username | `omini` | A dedicated account without 2-step verification |
| Password | | Stored encrypted by Omini, never logged, never written to the state folder |
| Verify the TLS certificate (Advanced) | off | DSM uses a self-signed certificate by default |
| Timeout, seconds (Advanced) | `15` | How long to wait for each answer (5 to 120). A refused connection or a busy NAS (429, 503) is asked again, twice, with a pause; a `GET` that timed out, once (the sign-in, a `POST`, is not sent again after a timeout) |

## How it works

`GET /webapi/query.cgi?api=SYNO.API.Info&method=query&query=all` gives each API's path and versions (no session needed); every other request goes to that path (`/webapi/entry.cgi`) with `api`, `version`, `method` and the session id `_sid` ([DSM Login Web API guide](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf)). Session ids never reach the logs (the HTTP library's request log is turned off).

| API, method | Read for |
|---|---|
| `SYNO.API.Auth` `login` (POST, version 6), `logout` | The session (`format=sid`, `session=Omini`) |
| `SYNO.Core.System` `info` | `model`, `serial`, `firmware_ver`, `cpu_cores`, `ram_size` (MB), `up_time` (`hours:minutes:seconds`), `sys_temp` (essential) |
| `SYNO.Core.System` `info` with `type=network` | `nif`: `id`, `mac`, `addr`, `mask`, `ipv6` (`addr`, `prefix_len`); `gateway`, `v6gateway` |
| `SYNO.Core.Network` `get` | `server_name`, `gateway`, `v6gateway` |
| `SYNO.Core.Network.Interface` `list` | `ifname`, `status` (`connected`), `speed` (Mb/s), `ip`, `mask` |
| `SYNO.Core.System.Utilization` `get` | `cpu.user_load`, `system_load`, `other_load` (%); `memory.real_usage` (%) |
| `SYNO.Storage.CGI.Storage` `load_info` | `volumes` (`vol_path`, `fs_type`, `size.total`, `size.used`, `status`), `disks` (`name`, `temp`, `smart_status`) |
| `SYNO.Docker.Container` `list` (`limit=-1`, `type=all`) | `containers`: `name`, `image`, `status` |

An API the account may not use (code 105), that is not installed (codes 102 to 104: Container Manager missing), that answers another error code or a server error, or that times out leaves that data out (logged once) and never fails the collection; the connection test lists what the account may not read. A refused sign-in, a NAS out of reach or a missing system information fails it (Omini keeps the last good data).

## Known limitations

- **SMART status and volume health are not reported**: Omini's data model has no field for a disk's or a volume's health yet (a disk whose SMART status is not `normal`, or a degraded volume, is only written to the plugin's log).
- **No interface counters**: the API gives rates (`SYNO.Core.System.Utilization` `network`), not counters.
- **Bonds** (`bond0`, `ovs_bond0`) are reported as LAGs without their member ports: where DSM lists them was not found in the guides.
- **Updates**: only the installed version. Checking for an update makes DSM ask Synology's servers, a check the plugin never starts.
- **Containers** are the NAS's services, not devices: Container Manager does not give their networks in the list (see the Docker plugin for a Docker host's containers as devices).
- **Load averages** are not reported: the units of `1min_load` were not confirmed.

### Not verified on hardware

- Which APIs answer to a non-administrator account on DSM 7.1 and 7.2 (the README's account steps assume the system, storage and container APIs may need `administrators`).
- The fields of `SYNO.Core.System` `info` with `type=network` (`nif`, `ipv6`, `prefix_len`), and of `SYNO.Core.Network.Interface` `list` (`status`, `speed`).
- That `SYNO.Storage.CGI.Storage` `load_info` sizes are byte counts as strings and `temp` is 0 (or less) when a drive gives no reading.
- That `SYNO.Docker.Container` `list` takes `limit=-1` and `type=all` on Container Manager (DSM 7.2) and on the older Docker package.
- That `up_time` is always `hours:minutes:seconds` (no days).
- That DSM keeps a session alive between collections a minute apart, and how it reports one it closed (codes 106, 107, 119 are handled).

## Development

The plugin uses [uv](https://docs.astral.sh/uv/) and expects the Omini repository next to it (the SDK is in `../omini/sdk/python`):

```bash
uv run pytest          # tests, against answers shaped like the API (tests/fixtures)
uv run ruff check .    # lint
uv run ruff format .   # format
```

Run it from a local Omini without installing it: `OMINI_PLUGIN_DIRS=../omini-plugin-synology make run` in the Omini repository; every collection uses the current code.

## License

MIT
