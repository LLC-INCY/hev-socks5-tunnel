# Host-App Integration Guide for `app-filter`

This guide is for authors of the desktop client that spawns
`hev-socks5-tunnel`. The behaviour and schema are documented in
[app-filter.md](app-filter.md); this file covers what the *host app*
needs to do per platform.

## Common: control-socket protocol

Every platform supports a Unix-domain socket (or named pipe on Windows)
for live updates. Bind happens only when `app-filter.control-socket` is
set in `tunnel.yml`. Wire format is line-delimited JSON.

Commands the host can send:

```json
{"op":"add-app","path":"/usr/bin/curl"}
{"op":"remove-app","path":"/usr/bin/curl"}
{"op":"add-pid","pid":1234}
{"op":"remove-pid","pid":1234}
{"op":"set-mode","mode":"include"}      // or "exclude"
{"op":"set-unmatched","policy":"drop"}  // or "direct"
{"op":"reload"}
{"op":"status"}
```

Replies are `{"ok":true}` or `{"ok":false,"error":"..."}`. `status`
returns the full rule set + counters.

Asynchronous events from hev → host (only `bypass` in v1):

```json
{"event":"bypass","pid":1234,"path":"...","flow":{...}}
```

Single-client policy: a second connection while one is open gets
`{"ok":false,"error":"busy"}` and is closed immediately.

## Linux: cgroup-v2 + nftables

hev does no in-process lookup on Linux. The host app drives enforcement
via the kernel.

### One-time setup

```sh
# Create the cgroup. Name must match `app-filter.cgroup-name`.
sudo mkdir -p /sys/fs/cgroup/incy-tunnelled

# Make it writable by the user running the host (or run host as root).
sudo chown -R "$USER" /sys/fs/cgroup/incy-tunnelled
```

### nftables rule (include mode)

Mark packets from the cgroup, then policy-route them via the tunnel
table. Combine with the existing `not fwmark 1 table <T>` rule that
keeps hev's own SOCKS5 connect-back out of the loop.

```sh
sudo nft -f - <<'EOF'
table inet incy {
    chain output {
        type route hook output priority -100; policy accept;
        socket cgroupv2 level 1 "incy-tunnelled" meta mark set 0x100
    }
}
EOF

# Route mark 0x100 through table 100 (the tunnel).
sudo ip rule add fwmark 0x100 table 100
sudo ip route add default dev tun0 table 100
```

### Migrating PIDs

```sh
# Per app launch: write the PID into cgroup.procs.
echo $PID | sudo tee /sys/fs/cgroup/incy-tunnelled/cgroup.procs
```

### Exclude mode

Same recipe but invert the mark: mark traffic NOT in the cgroup, route
that via the TUN; cgroup members fall through to default. Or use a
second cgroup `incy-bypass` and skip it explicitly.

## macOS: in-process lookup

On macOS hev resolves the owning process per flow via `proc_pidfdinfo`.
Host app responsibilities are minimal:

- Spawn hev with the desired `tunnel.yml`. Bundle ids in `apps:` are
  resolved at parse time via Launch Services.
- For exclude mode: subscribe to `bypass` events on the control socket.
  When you receive one, install a bypass route. macOS doesn't have a
  per-PID firewall API as clean as Windows WFP; the typical approach is
  to install a more-specific route for the destination IP via the host's
  default gateway *before* the app retries the connection. This is
  inherently racy — design your UI around the assumption that a
  newly-toggled exclude rule may take a connection or two to settle.
- macOS Network Extension users: if your client already runs an
  `NEPacketTunnelProvider`, you can skip hev's lookup entirely and use
  `NEFilterProvider` rules — but that's outside hev's scope.

The lookup uses non-privileged APIs (`proc_pidfdinfo` works for the
current user's processes). Cross-user PIDs return `EPERM`; hev counts
those as `lookup-failed` and treats the flow as unmatched. Since hev is
typically spawned as root by the helper that opens the utun device, this
should rarely fire.

## Windows: in-process lookup + WFP

hev resolves PIDs via `GetExtendedTcpTable`/`GetExtendedUdpTable` and exe
paths via `QueryFullProcessImageNameW` with
`PROCESS_QUERY_LIMITED_INFORMATION` (no admin needed for same-user PIDs).

For exclude mode the host installs a per-process WFP filter when a
`bypass` event arrives:

```c
// Pseudocode — see the Microsoft WFP samples for full setup.
FWPM_FILTER0 filter = {0};
filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
filter.action.type = FWP_ACTION_PERMIT;

FWPM_FILTER_CONDITION0 cond = {0};
cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
cond.matchType = FWP_MATCH_EQUAL;
cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
cond.conditionValue.byteBlob = appIdBlobFromPath(L"C:\\...\\spotify.exe");

filter.numFilterConditions = 1;
filter.filterCondition = &cond;
FwpmFilterAdd0(engine, &filter, NULL, NULL);
```

The filter must be installed in a sublayer with higher weight than the
TUN's catch-all route, otherwise the route grabs the connection first.
The "right" sublayer depends on your TUN driver (Wintun, WireGuard,
etc); test it.

UWP packaged apps are not supported in v1. If you need them, file an
issue with the package full name format you want hev to match against.

## Operational notes

- **Logging.** Set `log-level: debug` to see one line per filter
  decision. Rate-limited to 100/s per (decision, path) pair.
- **Counters.** `{"op":"status"}` returns lifetime counters
  (`matched`, `unmatched`, `lookup-failed`, `cache-hits`,
  `cache-misses`). Reset on hev restart.
- **Stale sockets.** If hev crashes, the Unix-domain socket file is
  left behind. The next start unlinks any existing AF_UNIX socket at
  the configured path before binding. Regular files at that path are
  *not* removed — bind will fail with a clear log line.
- **Hot-reload scope.** Only the `app-filter` block is hot-reloadable
  (via `add-app`/`remove-app`/`set-mode`/`set-unmatched`). Changes to
  `tunnel.*` or `socks5.*` still require a hev restart.
- **Lookup failures are not crashes.** If `proc_pidfdinfo` /
  `GetExtendedTcpTable` can't resolve the owner, hev counts it under
  `lookup-failed` and treats the flow as unmatched. Exclude mode falls
  through to bridge; include mode applies the `unmatched` policy
  (drop or direct).
