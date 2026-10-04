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

Public endpoint discovery uses one immutable IP-literal STUN destination. The
fork supplies that endpoint to netcheck through a transient STUN-only descriptor;
it is never installed as a DERP map, and send-time enforcement rejects every
other netcheck destination. LAN gateway port mapping and validated direct peer
candidates remain available for NAT traversal and network mobility.

While a direct-only instance has an authorized peer, a node key, and an online
network, its existing randomized 20–26-second STUN refresh remains active during
application idle. Each periodic refresh also retries authenticated discovery to
the peer's known direct candidates, subject to the existing per-endpoint rate
limit. STUN alone does not open destination-specific NAT mappings to that peer.
This bounded retry replaces the missing idle DERP wake-up path; it sends no
application payload or extra coordination message. Removed/expired peers are not
probed, and offline, homeless, keyless, or closed instances stop probing.

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
- `wgengine.Config.DirectOnly`, its fixed STUN/node/discovery identity fields,
  and `magicsock.DirectOnlyCounters`, which carry and audit the structural
  policy below tsnet.
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
