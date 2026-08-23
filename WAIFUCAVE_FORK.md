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
Public endpoint discovery uses one immutable IP-literal STUN destination. The
fork supplies that endpoint to netcheck through a transient STUN-only descriptor;
it is never installed as a DERP map, and send-time enforcement rejects every
other netcheck destination. LAN gateway port mapping and validated direct peer
candidates remain available for NAT traversal and network mobility.

Ordinary upstream behavior outside Waifus mode must remain unchanged. Runtime
counters and packet ledgers are regression evidence, not the enforcement
boundary.

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
