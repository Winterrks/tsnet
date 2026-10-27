# WaifuCave direct-only Tailscale fork

This repository is a narrowly scoped fork of
[tailscale/tailscale](https://github.com/tailscale/tailscale) for the embedded
Discord Waifus remote-management data plane. It preserves the upstream module
identity (`tailscale.com`) so downstream code can pin one reviewed fork commit
without rewriting upstream imports.

This project is not affiliated with, endorsed by, or supported by Tailscale
Inc. The upstream BSD-3-Clause license, patent grant, source headers, and
third-party notices remain authoritative and must be preserved.

## Pinned baseline

- Upstream tag: `v1.102.2`
- Upstream commit: `eb67e5dcbe145d63e1128b9b4b630f8a82da101f`
- Go version: `1.26.5`
- Baseline review date: `2026-08-23`

`WAIFUCAVE_UPSTREAM.lock` is the machine-readable source for these pins. Fork
CI rejects a mismatch between that file, `go.mod`,
`go.toolchain.version`, and the checked-out Git history.

Before fork changes, the following upstream suites passed on macOS ARM64 with
Go 1.26.5. Tests that create local sockets and network monitors required an
unsandboxed local test environment.

```text
go test ./control/controlclient ./ipn/ipnlocal ./tsnet ./wgengine/...
go test -race ./control/controlclient ./ipn/ipnlocal ./tsnet ./wgengine/magicsock
go test .
```

## Direct-only invariant

The Waifus build uses the `waifus_direct_only` build tag and an immutable
direct-only construction policy. In that mode, application data may travel
only over direct peer-to-peer UDP/WireGuard paths. DERP, peer relay, TURN,
general proxying, exit nodes, subnet routing, DNS, SSH, Serve/Funnel,
LocalAPI, and unrelated Tailscale services must be structurally unavailable.
A peer with no validated direct path receives a typed direct-unavailable
result; the build never falls back to a relay.

Waifus mode accepts only pair-isolated maps, pins node/discovery identities and
overlay addresses for the process lifetime, synthesizes its own TCP filter for
one immutable application port, and exposes no generic address or port dialer.
The private helper supplies the node private key, stable node ID, and discovery
private key before engine construction. Empty local state is initialized from
that identity; missing, corrupt, rotated, or mismatched state fails with
`repair_required` and is never silently regenerated. Engine reconfiguration
may temporarily clear the node key to stop after a rejected map, but only the
original helper-owned key can be restored.

The injected client contract uses successful full-map status envelopes only.
Interactive login URLs, map-less successful status, incremental peer/filter/
profile updates, and out-of-band discovery-key patches are rejected. Every
node carries a valid empty `Hostinfo` object; any populated host metadata is
forbidden. A full valid map is also the direct rendezvous signal: newly
advertised endpoints are proactively probed, while the existing rate limiter
suppresses redundant probes. This replaces the DERP `CallMeMaybe` path without
adding another relay or long-lived coordination data path.

Both accepted and dialed application streams are bound to the exact approved
peer key. `RefreshWaifusPeerAuthorizations` re-evaluates the local authorizer
without coordination, denies new flows immediately, closes revoked streams,
allows a bounded close-packet drain while the WireGuard route still exists,
and only then removes the peer. Other approved pair edges remain installed.
An approved peer that cannot establish direct UDP before the caller's deadline
returns `ErrWaifusDirectUnavailable`; no relay attempt follows.

Public endpoint discovery uses a fixed list of one to eight distinct IP-literal
STUN destinations, copied at construction. The fork supplies them to netcheck
through a transient STUN-only descriptor with one region per destination; it is
never installed as a DERP map, and send-time enforcement rejects every netcheck
destination outside the list. Every refresh probes every listed destination
(netcheck `ProbeAllRegions`, which also records which region reported which
IPv4 mapping) instead of only the fastest few, because some NATs keep the
mapped port but choose the public IPv4 address per destination from a pool. The
main socket's own current addresses (netcheck's first responder and every
address several destinations reported) are advertised first. LAN gateway port
mapping and validated direct peer candidates remain available for NAT traversal
and network mobility.

Such a pool NAT's choice is sticky per socket and destination, so the main
socket can see one address on every STUN destination while its traffic to the
peer leaves through another, which the peer's address-and-port dependent filter
then drops. Direct-only magicsock therefore tracks every public IPv4 address
observed on the current network, with the distinct STUN destinations that
reported it. An address is admitted to the pool only after two different
destinations reported it (from any socket), so one lying or spoofed STUN
destination cannot add one; addresses in reserved, private, shared,
documentation, benchmarking, multicast, or Tailscale ranges are never tracked.
At most eight addresses are admitted and sixteen tracked (unadmitted ones are
evicted first), each is forgotten after 30 minutes unobserved, and the pool is
cleared on a rebind, network loss, a change of the default-route interface or
its addresses, or a main-socket report that shares no address with it (a
network change under the same interface and local address). When the main
socket's observations of admitted addresses share one mapped port and that port
either equals the local port or one socket saw two admitted addresses with one
port, each admitted address is advertised, after the main socket's own
addresses, as a server-reflexive candidate with the current mapped port. To
learn the pool quickly, the first refresh on a network (and, at most once a
minute, any refresh while no round has been answered yet or an admitted address
has gone 15 minutes unobserved) also runs a learning round beside the regular
report: three short-lived extra UDP sockets, made immune to ICMP-induced read
errors like the main sockets, each send a binding request, retransmitted at
most twice, to every IPv4 destination of the same fixed STUN list and are
closed within two seconds. Only the public addresses they observe are kept;
their own ports are never advertised. Their sends go through the same
allow-list as netcheck and count against the egress tripwire otherwise, and the
source audit pins the guard, the ICMP setting, and the two socket-open sites.
In the in-memory two-NAT lab
(`wgengine/magicsock/directonly_natpool_lab_test.go`: a two-address
port-preserving pool NAT against a single-address port-preserving host NAT,
both address-and-port dependent), the fork before pool learning connected in
only six of the eight main-socket assignments and advertised both addresses in
four; with pool learning every assignment advertises both and connects at once.
A listed STUN server that forges a new address on the real port for every
request gets none into the pool.

Privacy: the STUN operators of the helper's compiled list (Cloudflare, Google,
Twilio, Nextcloud, sipgate, and BlackBerry) see the device's public address and
mapped port on every refresh. Because the helper prefers a stable per-pair UDP
port, they can link the same device across networks and over time; they see no
identity, pairing, or application data.

While a direct-only instance has an authorized peer, a node key, and an online
network, its existing randomized 20–26-second STUN refresh remains active during
application idle. Each periodic refresh also retries authenticated discovery to
the peer's known direct candidates, subject to the existing per-endpoint rate
limit. STUN alone does not open destination-specific NAT mappings to that peer.
This bounded retry replaces the missing idle DERP wake-up path; it sends no
application payload or extra coordination message. Removed/expired peers are not
probed, and offline, homeless, keyless, or closed instances stop probing.

Path formation does not wait for scheduled retries either. An authenticated
disco ping from a peer that has no trusted direct path is answered at once with
a ping back to its source, outside the regular per-endpoint interval but at
most once per second per address: the peer's NAT is evidently open toward that
address, which is exactly what a DERP `CallMeMaybe` would have announced. While
no trusted direct path exists, magicsock keeps a copy of the most recent
WireGuard handshake initiation or response it was asked to send (one message,
never transport data, at most five seconds old) and sends it over the direct
address as soon as a disco pong validates one, instead of leaving it to
wireguard-go's five-second retransmission. The first time a direct path to a
peer validates, the engine also starts a WireGuard handshake through the new
`magicsock.Options.DirectPathUpFunc` hook, unless a held handshake was just
sent or WireGuard itself completed a handshake with the peer meanwhile (a
packet that merely looks like a handshake cannot suppress it), and only while
the embedding runtime still authorizes the peer
(`wgengine.Config.DirectOnlyPeerAuthorized`), so a peer whose revocation is
draining never receives a new initiation. A peer that restarted therefore
replaces stale session keys immediately instead of after wireguard-go's
15-second keepalive timeout. The rendezvous answer goes to the source address
of a ping that authenticated with the authorized peer's discovery key; the
held handshake and the path-up handshake go only to a direct address that a
disco pong validated. None of them uses DERP, a relay, or any other path.
`wgengine/magicsock/directonly_rendezvous_test.go` measures the effect on an
in-memory two-NAT topology (endpoint-independent mapping, address-and-port
dependent filtering, no DERP):

| case (coordination delay) | before | after |
| --- | --- | --- |
| first contact (1 s) | 5.0 s | 1.0 s |
| first contact (3 s) | 10.3 s | 3.0 s |
| remote restart, new port (1 s) | 5.0 s | 1.0 s |
| remote restart, new port (3 s) | 10.0 s | 3.0 s |
| remote restart, same port (3 s) | 0.0 s | 0.0 s |
| host restart, new port (3 s) | 20.3 s | 3.8 s |
| host restart, same port (3 s) | 15.5 s | 0.8 s |

Ordinary upstream behavior outside Waifus mode must remain unchanged. Runtime
counters and packet ledgers are regression evidence, not the enforcement
boundary.

## Helper-facing delta

The intentionally added public seams are:

- `tsnet.WaifusControlConfig`, the two-value control profile enum, immutable
  helper-owned transport identity, fixed application port, local pair
  authorizer, and injected client factory.
- `tsnet.Server.DialWaifusPeer` and
  `tsnet.Server.RefreshWaifusPeerAuthorizations`, the only Waifus-specific
  dial and offline-revocation operations.
- `ipnlocal.WithControlClientFactory`,
  `ipnlocal.WithWaifusNetworkMapPolicy`, and
  `ipnlocal.WithWaifusLocalIdentity`, which are construction-only backend
  options.
- `magicsock.Options.DirectPathUpFunc`, the direct-only first-path handshake
  hook the engine installs, and `wgengine.Config.DirectOnlyPeerAuthorized`,
  which tsnet sets from the pair authorizer; both are ignored outside
  direct-only mode, and without an authorizer no such handshake starts.
- `wgengine.Config.DirectOnly`, its fixed STUN list/node/discovery identity
  fields, `magicsock.MaxDirectSTUNEndpoints`,
  `magicsock.ValidDirectOnlySTUNEndpoints`, and
  `magicsock.DirectOnlyCounters`, which carry, bound, and audit the structural
  policy below tsnet.
- `netcheck.GetReportOpts.ProbeAllRegions`, which makes every report probe
  and wait for every region of the transient STUN-only descriptor.
- `magicsock.Conn.RebindToNewPort`, a recovery/test hook that intentionally
  requests a fresh UDP socket tuple when no preferred port is configured and
  otherwise honors that explicit port. Callers follow it with `ReSTUN`.

The public fake coordinator in `tstest/waifuscontrol` and the
`cmd/waifus-direct-spike` tests exercise production and staging construction,
host-plus-two-remotes isolation, malicious maps, concurrent authenticated
streams, four-direction endpoint migration, offline revoke-one behavior, and
the typed hard-unavailable result. On Linux, the mandatory namespace matrix
adds an isolated loopback-only network, netem impairment, and packet capture:

```text
go test -tags=waifus_direct_only ./cmd/waifus-direct-spike ./tstest/waifuscontrol
sudo -n ./tool/waifus-spike/run-netns-matrix.sh
```

The packet gate requires observed STUN, discovery, and encrypted direct UDP,
and rejects outer TCP, DNS, or non-loopback egress. It cannot be closed by a
compile-only result.

Fork CI also launches the same lifecycle natively on `macos-26`
(`darwin/arm64`), `windows-2025` (`windows/amd64`), `windows-11-arm`
(`windows/arm64`), and `ubuntu-24.04-arm` (`linux/arm64`). Linux AMD64 runs the
stronger namespace matrix above. A static `linux/arm/v7` harness additionally
runs under QEMU as an ABI smoke test; that emulation is identified separately
and does not substitute for later representative ARMv7 hardware evidence.

## Public/private boundary

This public fork contains only the reusable direct-only data-plane seam and
public fake-control feasibility harness. It must never contain WaifuCave
activation credentials, Worker secrets, private coordination encodings,
installation keys, production pair records, or product-wide shared secrets.
The private `waifucave/ts-connect` helper owns product coordination and pins an
exact reviewed commit from this repository.

## Updating from upstream

Each update is a manual, reviewable patch-series operation:

1. Select and record an immutable upstream tag, commit, and Go version.
2. Create a new review branch from that exact upstream commit.
3. Reapply the bounded Waifus patch series; never auto-merge upstream.
4. Run focused, race, source-audit, malicious-map, packet/egress, network
   namespace, and supported-platform tests.
5. Review the complete diff against the recorded upstream commit.
6. Publish a new immutable fork commit only after the feasibility gate passes.
7. Update the private helper pin only after its own full suite passes.

Intel macOS (`darwin/amd64`) is intentionally outside the v1 platform gate and
is tracked as a later follow-up.
