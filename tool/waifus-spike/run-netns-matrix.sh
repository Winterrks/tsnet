#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "waifus netns matrix requires Linux" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "waifus netns matrix requires root (CI invokes it with sudo -n)" >&2
  exit 1
fi
for command_name in ip tc tcpdump awk git timeout; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "missing required command: ${command_name}" >&2
    exit 1
  fi
done

repository_root="${WAIFUS_REPOSITORY_ROOT:-$(git rev-parse --show-toplevel)}"
go_binary="${GO_BINARY:-$(command -v go)}"
namespace_name="waifus-spike-$$"
artifact_owned=false
if [[ -n "${WAIFUS_SPIKE_ARTIFACT_DIR:-}" ]]; then
  artifact_dir="${WAIFUS_SPIKE_ARTIFACT_DIR}"
  mkdir -p "${artifact_dir}"
else
  artifact_dir="$(mktemp -d /tmp/waifus-spike-artifacts.XXXXXX)"
  artifact_owned=true
fi
test_binary="${artifact_dir}/waifus-direct-spike.test"
packet_capture="${artifact_dir}/waifus-direct-spike.pcap"
packet_ledger="${artifact_dir}/packet-ledger.txt"
tcpdump_pid=""

cleanup() {
  if [[ -n "${tcpdump_pid}" ]]; then
    kill "${tcpdump_pid}" >/dev/null 2>&1 || true
    wait "${tcpdump_pid}" >/dev/null 2>&1 || true
  fi
  ip netns exec "${namespace_name}" tc qdisc del dev lo root >/dev/null 2>&1 || true
  ip netns del "${namespace_name}" >/dev/null 2>&1 || true
  if [[ "${artifact_owned}" == true && "${artifact_dir}" == /tmp/waifus-spike-artifacts.* ]]; then
    rm -rf -- "${artifact_dir}"
  fi
}
trap cleanup EXIT

cd "${repository_root}"
GOTOOLCHAIN=local CGO_ENABLED=0 "${go_binary}" test -c \
  -tags=waifus_direct_only \
  -o "${test_binary}" \
  ./cmd/waifus-direct-spike

ip netns add "${namespace_name}"
ip -n "${namespace_name}" link set lo up

ip netns exec "${namespace_name}" tcpdump -i any -U -nn -s 0 \
  -w "${packet_capture}" "udp or tcp" >/dev/null 2>&1 &
tcpdump_pid="$!"
capture_ready=false
for _ in {1..100}; do
  if ! kill -0 "${tcpdump_pid}" >/dev/null 2>&1; then
    echo "tcpdump exited before the feasibility matrix started" >&2
    wait "${tcpdump_pid}" || true
    exit 1
  fi
  if [[ -s "${packet_capture}" ]]; then
    capture_ready=true
    break
  fi
  sleep 0.05
done
if [[ "${capture_ready}" != true ]]; then
  echo "tcpdump did not become ready" >&2
  exit 1
fi

timeout --signal=TERM 3m ip netns exec "${namespace_name}" "${test_binary}" \
  -test.run '^TestDirectOnlyPairLifecycleAndOfflineRevocation$' \
  -test.count=1

# Repeat the direct lifecycle with an impaired loopback path. The namespace has
# no external interface, so every emitted packet remains auditable and local.
ip netns exec "${namespace_name}" tc qdisc replace dev lo root netem delay 20ms 5ms
timeout --signal=TERM 3m ip netns exec "${namespace_name}" "${test_binary}" \
  -test.run '^TestDirectOnlyPairLifecycleAndOfflineRevocation$' \
  -test.count=1
ip netns exec "${namespace_name}" tc qdisc del dev lo root

timeout --signal=TERM 1m ip netns exec "${namespace_name}" "${test_binary}" \
  -test.run '^TestDirectOnlyUnavailableNeverRelays$' \
  -test.count=1

kill "${tcpdump_pid}" >/dev/null 2>&1 || true
wait "${tcpdump_pid}" >/dev/null 2>&1 || true
tcpdump_pid=""

count_packets() {
  local filter="$1"
  tcpdump -nn -r "${packet_capture}" "${filter}" 2>/dev/null | awk 'END { print NR + 0 }'
}

total_udp="$(count_packets 'udp')"
stun_udp="$(count_packets 'udp and udp[12:4] = 0x2112a442')"
discovery_udp="$(count_packets 'udp and udp[8:2] = 0x5453 and udp[10:4] = 0xf09f92ac')"
local_mapping_udp="$(count_packets 'udp and (port 5351 or port 1900)')"
tcp_packets="$(count_packets 'tcp')"
dns_packets="$(count_packets 'port 53')"
escaped_packets="$(count_packets '(ip and not (src net 127.0.0.0/8 and dst net 127.0.0.0/8)) or (ip6 and not (src host ::1 and dst host ::1))')"
direct_encrypted_udp="$((total_udp - stun_udp - discovery_udp - local_mapping_udp))"

{
  echo "namespace=${namespace_name}"
  echo "total_udp_packets=${total_udp}"
  echo "stun_packets=${stun_udp}"
  echo "candidate_discovery_packets=${discovery_udp}"
  echo "local_mapping_packets=${local_mapping_udp}"
  echo "direct_encrypted_packets=${direct_encrypted_udp}"
  echo "tcp_packets=${tcp_packets}"
  echo "dns_packets=${dns_packets}"
  echo "non_loopback_packets=${escaped_packets}"
} >"${packet_ledger}"

if (( total_udp == 0 || stun_udp == 0 || discovery_udp == 0 || direct_encrypted_udp == 0 )); then
  echo "packet capture did not exercise every declared direct-only UDP class" >&2
  cat "${packet_ledger}" >&2
  exit 1
fi
if (( tcp_packets != 0 || dns_packets != 0 || escaped_packets != 0 )); then
  echo "packet capture observed forbidden TCP, DNS, or non-loopback egress" >&2
  cat "${packet_ledger}" >&2
  exit 1
fi

cat "${packet_ledger}"
if [[ "${artifact_owned}" == false ]]; then
  echo "packet artifacts: ${artifact_dir}"
fi
