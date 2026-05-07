# Per-Application Routing (`app-filter`)

Status: design, pending review. No code in this commit.

## 1. Goals and non-goals

**Goals**

- Selectively include or exclude traffic from specific local processes, decided at the moment a TCP/UDP flow is bridged from lwIP to the SOCKS5 outbound.
- Drive that decision from outside the binary: static config in `tunnel.yml`, plus live updates over a control socket.
- Stay self-contained — no new build-time deps (no libnftnl, no NetworkManager, no MS WPP, no LaunchServices link beyond what's already weak-linkable on macOS).
- Strictly opt-in. With no `app-filter:` block present, behaviour is identical to today: every TUN packet is tunnelled.

**Non-goals**

- Per-domain or per-destination filtering. That's a different layer.
- Filtering of forwarded traffic the host did not originate (we only see what the host kernel routes into our TUN).
- UWP/packaged-app identity on Windows in v1 (deferred — see §3.3).
- Linux userspace per-socket-owner lookup as a fallback (cgroup-v2 only — see §3.1).

## 2. Schema

New top-level block in `tunnel.yml`:

```yaml
app-filter:
  mode: include              # include | exclude
  apps:
    - "/Applications/Firefox.app/Contents/MacOS/firefox"
    - "com.spotify.client"
    - "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    - "/usr/bin/curl"
  pids: [1234, 5678]         # optional: explicit PIDs override apps
  uids: [501]                # optional: include/exclude by UID
  unmatched: drop            # drop | direct, default: drop
  control-socket: "/tmp/hev-incy.sock"   # optional, see §5
  cgroup-name: "incy-tunnelled"          # Linux only, see §3.1
```

**Field semantics**

- `mode: include` — only flows whose owning process matches `apps`/`pids`/`uids` are bridged to SOCKS5. Everything else is handled per `unmatched`.
- `mode: exclude` — matching flows bypass the tunnel; everything else is bridged as today.
- `apps` — platform-specific identifiers. Detected by shape at config load:
  - Starts with `/` → POSIX exe path (macOS, Linux).
  - Drive-lettered or UNC path (`^[A-Za-z]:\\` or `^\\\\`) → Windows exe path.
  - Reverse-DNS shape (`^[a-z0-9.-]+$` and contains `.`) → macOS bundle id, resolved at load time via `LSCopyApplicationURLsForBundleIdentifier` + `CFBundleCopyExecutableURL`. A bundle id may resolve to a *set* of exe paths (multiple installs); all are added. Re-resolved on `reload`.
- `pids` — exact numeric PIDs. Not stable across app restarts; intended for short-lived rules pushed via the control socket.
- `uids` — POSIX UID match (Linux/macOS only; ignored on Windows with a one-time warning).
- `unmatched` — what to do with flows that don't match in `mode: include`. Default `drop`. `direct` requires the host has set up an escape route (see §4).
- `control-socket` — if set, bind a Unix-domain socket (Linux/macOS) or named pipe (Windows). If unset, no socket is opened. There is no default path.
- `cgroup-name` — Linux only. Name of the cgroup-v2 the host migrates PIDs into; hev does not create or modify the cgroup, only reads the name for logging and `status` reporting.

**Backward compatibility.** When the entire `app-filter:` block is absent, no filter code paths run, no extra threads, no extra fds. This is the contract for existing deployments.

## 3. Per-OS lookup strategy

The filter decision happens once per *flow* at the lwIP boundary, not per packet. Two real insertion points exist in the codebase today:

- **TCP**: `tcp_accept_handler` at `src/hev-socks5-tunnel.c:163`. The lwIP `pcb` here exposes the local app's source via `pcb->remote_ip`/`pcb->remote_port` (lwIP is the "server" side from the app's POV) and the destination via `pcb->local_ip`/`pcb->local_port`. The decision must be made *before* `hev_socks5_session_tcp_new` constructs the SOCKS5 client at `src/hev-socks5-session-tcp.c:299`. Concretely: insert immediately after the `if (!run) return ERR_RST;` check at `src/hev-socks5-tunnel.c:174`, before line 176.
- **UDP**: `udp_recv_handler` at `src/hev-socks5-tunnel.c:227`. The first packet of a flow gives us source via the `addr`/`port` arguments and destination via `pcb->local_ip`/`pcb->local_port`. Decision is made after the mapdns short-circuit at line 249 and before `hev_socks5_session_udp_new` at line 251.

The 5-tuple available at both points is sufficient for every per-OS lookup API below. The local app's source port (`pcb->remote_port` for TCP, `port` arg for UDP) is the primary key.

### 3.1 Linux — `SOCK_DIAG` netlink (in-process lookup)

**Update (`2.14.4-incy.5`):** the cgroup-v2 design below is no longer
required. Linux now resolves the owning process per flow via
`NETLINK_INET_DIAG`, modeled on sing-box's
`common/process/searcher_linux.go`:

1. Lazily open one `AF_NETLINK/NETLINK_INET_DIAG` socket per (family,
   proto). Reuse for the lifetime of hev.
2. Send `inet_diag_req_v2` with the exact 5-tuple. The kernel returns
   one `inet_diag_msg` carrying `idiag_uid` and `idiag_inode`.
3. uid → `{inode → exe_path}` cache, 1s TTL, built by walking `/proc`
   and filtering by `st_uid` per pid dir, then `readlink` on every
   `/proc/<pid>/fd/*` to find `socket:[INODE]`.

This works for the user running hev (typically root in our deployment)
and needs no host-app cooperation. Cross-user PIDs return as
`lookup-failed` and are treated as unmatched.

The cgroup-v2/nft path documented below still works as a fallback /
co-existence option (see `INTEGRATION.md`) but is no longer the
default story.

### 3.1.1 Linux — legacy: cgroup-v2 (no in-process lookup)

hev does **not** look up PIDs on Linux. The host app:

1. Creates a cgroup-v2 (e.g. `/sys/fs/cgroup/incy-tunnelled`).
2. Writes target PIDs into `cgroup.procs`.
3. Installs an nftables rule on the OUTPUT chain that matches `socket cgroupv2 level 1 "incy-tunnelled"` and either policy-routes into the TUN's table (include mode) or skips it (exclude mode).

hev's role on Linux is limited to:

- Accepting `app-filter.cgroup-name` for logging and `status` reporting.
- Continuing to set `socks5.mark: 1` on the SOCKS5 outbound socket (existing behaviour at `src/hev-socks5-session-tcp.c:210` and `src/hev-socks5-session-udp.c:242`) so the `not fwmark 1 table <T>` rule keeps the SOCKS5 client's own connection out of the TUN.

The flow-level lookup hooks described in §3.2/§3.3 are **compiled out** on Linux. If `app-filter.apps`/`pids`/`uids` are set on Linux without the host having installed the corresponding nft rule, hev logs a warning at startup but does not refuse to run — the host app may want to drive enforcement via the control socket instead (see §5).

**Userspace fallback explicitly rejected.** `/proc/net/tcp` + `/proc/<pid>/fd` scanning is O(processes × fds) per flow and unacceptable on the hot path. Kernels without cgroup-v2 socket matching (pre-4.18) get a clear startup error; users disable `app-filter` to run.

### 3.2 macOS — `proc_pidfdinfo`

Per-flow procedure (called from the insertion points in §3):

1. Build the lookup key: `(proto, local_addr, local_port, remote_addr, remote_port)`. "Local" = the host process's source side (= lwIP's `remote_*` for TCP).
2. Enumerate PIDs via `proc_listpids(PROC_ALL_PIDS, 0, ...)`.
3. For each PID, list its fds via `proc_pidinfo(pid, PROC_PIDLISTFDS, ...)`.
4. For each fd of type `PROX_FDTYPE_SOCKET`, call `proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof info)`.
5. Match `info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport` (network-byte order — convert with `ntohs`) and `insi_laddr` against the source side of our key. Skip if no match.
6. Map PID → exe path via `proc_pidpath(pid, buf, sizeof buf)`.
7. Compare against the resolved exe-path set; decide include/exclude.

**Caching.** A flow's source port is unique-per-flow, so caching per-flow buys nothing. The only worthwhile cache is `pid → exe_path` with a 60 s TTL, invalidated on the next call to `proc_pidpath` returning a different path or `ENOENT` (process exited / replaced). The slow step is `proc_pidfdinfo`; we accept ~50 µs per new flow.

**Permission model.** `proc_pidfdinfo` works for the current user's processes without elevation. For other-user PIDs we get `EPERM`; treat as "lookup failed", increment the `lookup-failed` counter, log once at debug, and treat the flow as unmatched. Since hev is started as root in this deployment (it opens the utun device), this should rarely fire — but the code path must not assume root.

**API surface used.** All from `<libproc.h>`, link `-lproc` is unnecessary (statically present on macOS). LaunchServices for bundle-id resolution is `-framework CoreServices` and is only invoked at config load, never on the hot path.

### 3.3 Windows — `GetExtendedTcpTable` / `GetExtendedUdpTable`

Per-flow procedure:

1. Build the lookup key as in §3.2.
2. Call `GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)` to size; allocate; call again to fill. Same for `AF_INET6`. Same for UDP via `GetExtendedUdpTable(... UDP_TABLE_OWNER_MODULE)`. v4 and v6 tables are separate; both are needed.
3. Walk the `MIB_TCPROW_OWNER_MODULE`/`MIB_UDPROW_OWNER_MODULE` rows, match on `dwLocalAddr`/`dwLocalPort` (and `dwRemoteAddr`/`dwRemotePort` for TCP — UDP rows don't carry the remote side, that's fine, local port + local addr is enough).
4. Map `dwOwningPid` → exe path via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)` + `QueryFullProcessImageNameW`. Use `PROCESS_QUERY_LIMITED_INFORMATION` (not `PROCESS_QUERY_INFORMATION`) so we work without elevation against same-user PIDs.
5. Compare against the resolved exe-path set (case-insensitive, normalize `\\\\?\\` prefixes).

**Caching.** Same as macOS: `pid → exe_path` with 60 s TTL, invalidated on PID handle reopen failure.

**UWP / packaged apps deferred.** If `QueryFullProcessImageNameW` returns a known host process (`svchost.exe`, `ApplicationFrameHost.exe`, `RuntimeBroker.exe`), log once at warn level: `app-filter: pid=N is a packaged-app host (P), not matched in v1`. Treat the flow as unmatched. Future work would add `OpenPackageInfoByFullName` / `GetPackageFullName` and a `package:<full-name>` schema shape.

**Permission model.** `PROCESS_QUERY_LIMITED_INFORMATION` succeeds for same-user processes without elevation. Cross-user PIDs return `ERROR_ACCESS_DENIED` → `lookup-failed`, log once, treat as unmatched.

### 3.4 Decision flow (all OSes that do in-process lookup)

```
on new flow (TCP accept | first UDP packet):
    if app-filter not configured:
        proceed as today
    if explicit pid in pids: decision = match
    elif uid match (POSIX): decision = match
    else:
        path = lookup_exe_path_for_flow(5-tuple)   # may return NULL
        if path == NULL:
            stat.lookup_failed++
            decision = unmatched
        elif path in resolved_apps_set:
            decision = match
        else:
            decision = unmatched
    if mode == include:
        bridge if decision == match, else apply unmatched-policy
    else:                              # exclude
        bridge if decision == unmatched, else apply unmatched-policy
                                       # (matched flows in exclude need bypass)
```

For **exclude mode on Windows and macOS**, "bypass" is not something hev can do alone — the packet has already entered the TUN. hev sends a `bypass` event over the control socket (see §5) so the host installs a per-process WFP exception (Windows) or the equivalent macOS NEFilterDataProvider rule. Without a control socket bound, exclude-mode matched flows on macOS/Windows are dropped with a warning logged once per PID.

## 4. Unmatched-flow semantics

The `app-filter.unmatched` knob picks between:

- **`drop` (default)** — TCP: return `ERR_RST` from `tcp_accept_handler` so the app sees connection refused. UDP: `udp_remove(pcb)` and discard the pbuf. No ICMP. The lwIP TCP path already uses this exact return value at `src/hev-socks5-tunnel.c:174` for the shutdown case, so the kernel-visible behaviour is identical to a session that fails to construct.
- **`direct`** — packet is silently *not* bridged into hev. On Linux this is naturally handled by the cgroup-v2 nft rule (the packet never reaches our TUN in the first place), so on Linux this knob is effectively unused. On macOS/Windows, "direct" is **not implementable from within hev** — once the packet is in the TUN, the host kernel has already committed to that route. To make `direct` work the host app must install an escape route (per-process or per-port) before the user toggles the rule. We document this as a host-app responsibility in `INTEGRATION.md` and emit a one-shot warning on startup if `unmatched: direct` is set on macOS/Windows without a `control-socket` (since the host needs the bypass events to install exceptions).

`loopback-fail` (synthesizing ICMP unreachable) is not offered. It complicates lwIP integration for marginal benefit over `drop`.

## 5. Control socket

Bound only when `app-filter.control-socket` is set. There is no default path and no default bind — silence is the secure default.

**Transport**

- Linux/macOS: `SOCK_STREAM` Unix-domain socket at the configured path, mode `0600`, owner = hev's effective UID. We rely on filesystem permissions for auth (per the §0 decision).
- Windows: named pipe `\\.\pipe\<basename>` derived from the configured path, with a security descriptor allowing only the owner SID.

**Wire format.** Line-delimited JSON, one object per `\n`. Replies are line-delimited JSON.

**Commands (host → hev)**

```json
{"op":"add-app","path":"/usr/bin/curl"}
{"op":"remove-app","path":"/usr/bin/curl"}
{"op":"add-pid","pid":1234}
{"op":"remove-pid","pid":1234}
{"op":"set-mode","mode":"exclude"}
{"op":"set-unmatched","policy":"direct"}
{"op":"reload"}
{"op":"status"}
```

**Replies (hev → host)**

```json
{"ok":true}
{"ok":false,"error":"unknown op"}
{"ok":true,"status":{
  "mode":"include","unmatched":"drop",
  "apps":["/usr/bin/curl"],"pids":[],"uids":[],
  "cgroup":"incy-tunnelled",
  "stats":{"matched":42,"unmatched":7,"lookup-failed":1,
           "cache-hits":120,"cache-misses":15}
}}
```

**Events (hev → host, asynchronous)**

```json
{"event":"bypass","pid":1234,"path":"/usr/bin/curl",
 "flow":{"proto":"tcp","src":"192.168.1.5:54321","dst":"1.1.1.1:443"}}
```

`bypass` events are emitted only in `mode: exclude` on macOS/Windows when a matched flow is detected and needs a host-installed route exception. Linux does not emit them (kernel handles bypass via nft).

**Reload semantics.** `reload` re-reads `tunnel.yml`. Only the `app-filter` block is hot-reloadable in v1 — changes to `tunnel.*` or `socks5.*` still require a restart and we explicitly reject them with `{"ok":false,"error":"only app-filter is hot-reloadable"}`.

**Concurrency.** A single connection at a time. New connections while one is open are accepted and immediately closed with `{"ok":false,"error":"busy"}`. The host app is single-threaded against this socket in our deployment.

## 6. Logging and metrics

At `log-level: debug`, every flow decision emits one line:

```
[app-filter] pid=1234 path=/usr/bin/curl decision=include flow=tcp/192.168.1.5:54321→1.1.1.1:443
```

When the lookup fails, `path=?` and `pid=-1`. The line is rate-limited to 100/s per (decision, path) pair to keep debug logs survivable under flood.

Counters exposed via the control socket's `status` op:

- `matched` — flows that hit a rule.
- `unmatched` — flows that didn't.
- `lookup-failed` — `proc_pidfdinfo`/`GetExtendedTcpTable` couldn't resolve (cross-user PID, race with process exit, etc).
- `cache-hits` / `cache-misses` — pid→path cache effectiveness.

Counters are 64-bit, monotonic, never reset within a process lifetime. Reset on hev restart.

## 7. Testing plan

- **Unit: lookup-failure resilience.** Inject a stub lookup function that returns NULL; verify the flow is treated as unmatched, the counter increments, and no crash. This is the "PID-resolution failure should never crash" requirement.
- **Unit: bundle-id resolution.** Mock `LSCopyApplicationURLsForBundleIdentifier` to return zero, one, and many URLs; verify the resolved-path set matches.
- **Unit: schema parser.** Absent `app-filter` block → no filter state allocated. Empty `apps: []` with `mode: include` → all flows unmatched. `pids: [self_pid]` → self is matched.
- **Unit: control-socket protocol.** Each op produces the expected reply; unknown ops return error; malformed JSON closes the connection without crashing.
- **Integration: macOS.** Spawn `curl` and a second helper; configure `apps: [curl]` `mode: include`; verify curl traffic is bridged and the helper is dropped. Verify `direct` mode on macOS without control socket logs the warn-once message.
- **Integration: Linux.** Configure `cgroup-name: test-cg`, install nft rule per `INTEGRATION.md`, migrate a PID, verify routing. (No in-process lookup is exercised on Linux.)
- **Integration: Windows.** Same as macOS, plus assert the `bypass` event fires in exclude mode.

## 8. Insertion-point cheat sheet

Single-page reference for the implementation phase:

| What | File:Line | Insert before |
|---|---|---|
| TCP filter check | `src/hev-socks5-tunnel.c:174` | `hev_socks5_session_tcp_new` at `:176` |
| UDP filter check | `src/hev-socks5-tunnel.c:249` | `hev_socks5_session_udp_new` at `:251` |
| 5-tuple source (TCP) | — | `pcb->remote_ip`, `pcb->remote_port` |
| 5-tuple dest (TCP) | — | `pcb->local_ip`, `pcb->local_port` |
| 5-tuple source (UDP) | — | `addr`, `port` args to `udp_recv_handler` |
| 5-tuple dest (UDP) | — | `pcb->local_ip`, `pcb->local_port` |
| Drop a TCP flow | `src/hev-socks5-tunnel.c:174` (pattern) | `return ERR_RST;` |
| Drop a UDP flow | new code | `udp_remove(pcb); pbuf_free(p); return;` |

## 9. Open questions deferred past v1

- UWP / packaged-app identity on Windows.
- Linux pre-4.18 fallback (currently: refuse to start with app-filter on).
- Per-domain rules (separate feature).
- Multi-cgroup on Linux (one `cgroup-name` for v1).
- Concurrent control-socket clients.
