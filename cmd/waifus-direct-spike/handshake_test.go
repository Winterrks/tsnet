// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/waifuscontrol"
	"tailscale.com/types/key"
)

// TestDirectOnlyFirstPathStartsAuthorizedHandshake checks the tsnet wiring of
// the path-up handshake: once an authorized pair's direct path validates,
// WireGuard completes a handshake before any application traffic exists.
func TestDirectOnlyFirstPathStartsAuthorizedHandshake(t *testing.T) {
	stunAddress, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	stunEndpoint := netip.MustParseAddrPort(stunAddress.String())
	host := spikeNode("path-up-host", waifuscontrol.RoleHost, 41, "100.64.0.41/32")
	remote := spikeNode("path-up-remote", waifuscontrol.RoleRemote, 42, "100.64.0.42/32")
	hub, err := waifuscontrol.New(host, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	if err := hub.ApprovePair(host.Name, remote.Name); err != nil {
		t.Fatal(err)
	}
	hostServer := newSpikeServer(t, hub, host, tsnet.WaifusControlProduction, "https://pair.waifucave.com", stunEndpoint)
	remoteServer := newSpikeServer(t, hub, remote, tsnet.WaifusControlProduction, "https://pair.waifucave.com", stunEndpoint)
	for _, server := range []*tsnet.Server{hostServer, remoteServer} {
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, node := range []waifuscontrol.Node{host, remote} {
		if err := hub.WaitForMap(ctx, node.Name, 1, mapHasDirectEndpoints); err != nil {
			t.Fatal(err)
		}
	}
	handshaken := func(server *tsnet.Server, peer key.NodePublic) bool {
		wgPeer, ok := server.Sys().Engine.Get().PeerByKey(peer)
		return ok && !wgPeer.LastHandshake().IsZero()
	}
	deadline := time.Now().Add(15 * time.Second)
	for !handshaken(hostServer, remote.PublicNodeKey()) || !handshaken(remoteServer, host.PublicNodeKey()) {
		if time.Now().After(deadline) {
			t.Fatal("no WireGuard handshake followed the first validated direct path")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
