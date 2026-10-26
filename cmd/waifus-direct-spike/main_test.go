// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/waifuscontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

const spikeApplicationPort uint16 = 43111

func TestDirectOnlyPairLifecycleAndOfflineRevocation(t *testing.T) {
	profiles := []struct {
		name       string
		profile    tsnet.WaifusControlProfile
		controlURL string
	}{
		{name: "production", profile: tsnet.WaifusControlProduction, controlURL: "https://pair.waifucave.com"},
		{name: "staging", profile: tsnet.WaifusControlStaging, controlURL: "https://pair-staging.waifucave.com"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			runDirectOnlyPairLifecycle(t, profile.profile, profile.controlURL)
		})
	}
}

func TestDirectOnlySinglePairLifecycle(t *testing.T) {
	stunAddress, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	stunEndpoint := netip.MustParseAddrPort(stunAddress.String())

	host := spikeNode("single-host", waifuscontrol.RoleHost, 21, "100.64.0.21/32")
	remote := spikeNode("single-remote", waifuscontrol.RoleRemote, 22, "100.64.0.22/32")
	hub, err := waifuscontrol.New(host, remote)
	if err != nil {
		t.Fatalf("new fake control: %v", err)
	}
	t.Cleanup(hub.Close)
	if err := hub.ApprovePair(host.Name, remote.Name); err != nil {
		t.Fatal(err)
	}

	hostServer := newSpikeServer(t, hub, host, tsnet.WaifusControlProduction, "https://pair.waifucave.com", stunEndpoint)
	remoteServer := newSpikeServer(t, hub, remote, tsnet.WaifusControlProduction, "https://pair.waifucave.com", stunEndpoint)
	for name, server := range map[string]*tsnet.Server{host.Name: hostServer, remote.Name: remoteServer} {
		if err := server.Start(); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
	}

	setupCtx, setupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer setupCancel()
	for _, node := range []waifuscontrol.Node{host, remote} {
		if err := hub.WaitForMap(setupCtx, node.Name, 1, mapHasDirectEndpoints); err != nil {
			t.Fatalf("wait for %s direct endpoints: %v", node.Name, err)
		}
	}
	if hostMap, remoteMap := hub.LastMap(host.Name), hub.LastMap(remote.Name); hostMap == nil || remoteMap == nil || len(hostMap.Peers) != 1 || len(remoteMap.Peers) != 1 {
		t.Fatalf("single-pair maps = host %v, remote %v", hostMap, remoteMap)
	}

	listener, err := hostServer.Listen("tcp", fmt.Sprintf(":%d", spikeApplicationPort))
	if err != nil {
		t.Fatalf("host application listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	application := newAuthenticatedEchoServer(listener, map[string]string{
		remote.Address.Addr().String(): "single-token",
	})
	t.Cleanup(application.Close)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Second)
	connection := dialAuthenticated(t, dialCtx, remoteServer, host.PublicNodeKey(), "single-token")
	dialCancel()
	t.Cleanup(func() { _ = connection.Close() })
	assertPong(t, connection, "single-pair")

	if err := hub.ProtocolError(); err != nil {
		t.Fatalf("fake-control protocol invariant: %v", err)
	}
	for name, server := range map[string]*tsnet.Server{host.Name: hostServer, remote.Name: remoteServer} {
		counters := server.Sys().MagicSock.Get().DirectOnlyCounters()
		if counters.DERPAttempts != 0 || counters.PeerRelayAttempts != 0 ||
			counters.EgressAttempts != 0 || counters.IdentityMutationAttempts != 0 {
			t.Fatalf("%s prohibited-path counters = %+v, want all zero", name, counters)
		}
	}
}

func TestDirectOnlyUnavailableNeverRelays(t *testing.T) {
	stunAddress, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	stunEndpoint := netip.MustParseAddrPort(stunAddress.String())

	host := spikeNode("blocked-host", waifuscontrol.RoleHost, 11, "100.64.0.11/32")
	remote := spikeNode("blocked-remote", waifuscontrol.RoleRemote, 12, "100.64.0.12/32")
	hub, err := waifuscontrol.New(host, remote)
	if err != nil {
		t.Fatalf("new fake control: %v", err)
	}
	t.Cleanup(hub.Close)
	if err := hub.ApprovePair(host.Name, remote.Name); err != nil {
		t.Fatal(err)
	}

	blockedSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve blocked endpoint: %v", err)
	}
	t.Cleanup(func() { _ = blockedSocket.Close() })
	blockedEndpoint := netip.MustParseAddrPort(blockedSocket.LocalAddr().String())
	if err := hub.SetEndpoints(host.Name, []netip.AddrPort{blockedEndpoint}); err != nil {
		t.Fatalf("set blocked host endpoint: %v", err)
	}

	server := newSpikeServer(t, hub, remote, tsnet.WaifusControlProduction, "https://pair.waifucave.com", stunEndpoint)
	if err := server.Start(); err != nil {
		t.Fatalf("start blocked remote: %v", err)
	}
	mapCtx, mapCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer mapCancel()
	if err := hub.WaitForMap(mapCtx, remote.Name, 1, mapHasDirectEndpoints); err != nil {
		t.Fatalf("wait for blocked direct map: %v", err)
	}
	blockedMap := hub.LastMap(remote.Name)
	peer := nodeFromMap(t, blockedMap, host.PublicNodeKey())
	if peer.Endpoints().Len() != 1 || peer.Endpoints().At(0) != blockedEndpoint || !blockedEndpoint.Addr().IsLoopback() {
		t.Fatalf("blocked fixture escaped its local endpoint: %v", peer.Endpoints())
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	connection, err := server.DialWaifusPeer(dialCtx, host.PublicNodeKey())
	dialCancel()
	if connection != nil {
		_ = connection.Close()
		t.Fatal("UDP-blocked fixture unexpectedly established a direct connection")
	}
	if !errors.Is(err, tsnet.ErrWaifusDirectUnavailable) {
		t.Fatalf("blocked dial error = %v, want %v", err, tsnet.ErrWaifusDirectUnavailable)
	}
	counters := server.Sys().MagicSock.Get().DirectOnlyCounters()
	t.Logf("blocked direct-only counters=%+v", counters)
	if counters.DERPAttempts != 0 || counters.PeerRelayAttempts != 0 ||
		counters.EgressAttempts != 0 || counters.IdentityMutationAttempts != 0 {
		t.Fatalf("blocked dial prohibited-path counters = %+v, want all zero", counters)
	}
	if err := hub.ProtocolError(); err != nil {
		t.Fatalf("blocked fake-control protocol invariant: %v", err)
	}
}

func runDirectOnlyPairLifecycle(t *testing.T, profile tsnet.WaifusControlProfile, controlURL string) {
	baselineGoroutines := runtime.NumGoroutine()
	stunAddress, closeSTUN := stuntest.Serve(t)
	t.Cleanup(closeSTUN)
	stunEndpoint := netip.MustParseAddrPort(stunAddress.String())

	host := spikeNode("host", waifuscontrol.RoleHost, 1, "100.64.0.1/32")
	remoteA := spikeNode("remote-a", waifuscontrol.RoleRemote, 2, "100.64.0.2/32")
	remoteB := spikeNode("remote-b", waifuscontrol.RoleRemote, 3, "100.64.0.3/32")
	hub, err := waifuscontrol.New(host, remoteA, remoteB)
	if err != nil {
		t.Fatalf("new fake control: %v", err)
	}
	t.Cleanup(hub.Close)
	if err := hub.ApprovePair(host.Name, remoteA.Name); err != nil {
		t.Fatal(err)
	}
	if err := hub.ApprovePair(host.Name, remoteB.Name); err != nil {
		t.Fatal(err)
	}

	servers := map[string]*tsnet.Server{}
	for _, node := range []waifuscontrol.Node{host, remoteA, remoteB} {
		server := newSpikeServer(t, hub, node, profile, controlURL, stunEndpoint)
		servers[node.Name] = server
		if err := server.Start(); err != nil {
			t.Fatalf("start %s: %v", node.Name, err)
		}
	}
	t.Logf("runtime surface after three peers: goroutines=%d baseline=%d", runtime.NumGoroutine(), baselineGoroutines)

	setupCtx, setupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer setupCancel()
	for _, node := range []waifuscontrol.Node{host, remoteA, remoteB} {
		if err := hub.WaitForMap(setupCtx, node.Name, 1, mapHasDirectEndpoints); err != nil {
			t.Fatalf("wait for %s direct endpoints: %v; generation=%d map=%v", node.Name, err, hub.EndpointGeneration(node.Name), hub.LastMap(node.Name))
		}
	}
	assertPairIsolation(t, hub, host, remoteA, remoteB)

	// A malicious coordinator tries each generic-tailnet expansion against
	// remote A. Every full status is rejected before engine mutation, then the
	// next valid pair-only map restores service.
	maliciousUpdates := []struct {
		name      string
		dialKey   key.NodePublic
		mutateMap func(*netmap.NetworkMap)
	}{
		{
			name:    "extra remote",
			dialKey: remoteB.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				nm.Peers = append(nm.Peers, nodeFromMap(t, hub.LastMap(host.Name), remoteB.PublicNodeKey()))
			},
		},
		{
			name:    "DERP map",
			dialKey: host.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				nm.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1}}}
			},
		},
		{
			name:    "peer relay",
			dialKey: host.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				hostNode := nm.Peers[0].AsStruct()
				hostNode.Hostinfo = (&tailcfg.Hostinfo{PeerRelay: true}).View()
				nm.Peers[0] = hostNode.View()
			},
		},
		{
			name:    "route",
			dialKey: host.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				hostNode := nm.Peers[0].AsStruct()
				hostNode.AllowedIPs = append(hostNode.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
				nm.Peers[0] = hostNode.View()
			},
		},
		{
			name:    "DNS",
			dialKey: host.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				nm.DNS.Proxied = true
			},
		},
		{
			name:    "arbitrary services",
			dialKey: host.PublicNodeKey(),
			mutateMap: func(nm *netmap.NetworkMap) {
				nm.CollectServices = true
			},
		},
	}
	for _, update := range maliciousUpdates {
		t.Run("reject-"+update.name, func(t *testing.T) {
			malicious := hub.LastMap(remoteA.Name)
			update.mutateMap(malicious)
			if err := hub.InjectMap(remoteA.Name, malicious); err != nil {
				t.Fatalf("inject malicious remote map: %v", err)
			}
			shortCtx, shortCancel := context.WithTimeout(context.Background(), time.Second)
			connection, err := servers[remoteA.Name].DialWaifusPeer(shortCtx, update.dialKey)
			shortCancel()
			if connection != nil {
				_ = connection.Close()
				t.Fatal("malicious map enabled a dial")
			}
			if !errors.Is(err, tsnet.ErrWaifusPeerUnavailable) {
				t.Fatalf("dial error = %v, want %v", err, tsnet.ErrWaifusPeerUnavailable)
			}
			nextDelivery := hub.DeliveryCount(remoteA.Name) + 1
			hub.Publish()
			if err := hub.WaitForMap(setupCtx, remoteA.Name, nextDelivery, mapHasDirectEndpoints); err != nil {
				t.Fatalf("recover valid remote A map: %v", err)
			}
		})
	}
	remoteBView := nodeFromMap(t, hub.LastMap(host.Name), remoteB.PublicNodeKey())
	if _, err := servers[remoteA.Name].Sys().MagicSock.Get().GetEndpointChanges(remoteBView); err == nil {
		t.Fatal("remote A's engine learned or probed remote B after rejected map injection")
	}

	listener, err := servers[host.Name].Listen("tcp", fmt.Sprintf(":%d", spikeApplicationPort))
	if err != nil {
		t.Fatalf("host application listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	application := newAuthenticatedEchoServer(listener, map[string]string{
		remoteA.Address.Addr().String(): "token-a",
		remoteB.Address.Addr().String(): "token-b",
	})
	t.Cleanup(application.Close)
	for _, node := range []waifuscontrol.Node{host, remoteA, remoteB} {
		t.Logf("%s port=%d generation=%d map=%s", node.Name, servers[node.Name].Sys().MagicSock.Get().LocalPort(), hub.EndpointGeneration(node.Name), hub.LastMap(node.Name).Concise())
	}

	dialACtx, dialACancel := context.WithTimeout(context.Background(), 15*time.Second)
	connectionA := dialAuthenticated(t, dialACtx, servers[remoteA.Name], host.PublicNodeKey(), "token-a")
	dialACancel()
	t.Cleanup(func() { _ = connectionA.Close() })
	dialBCtx, dialBCancel := context.WithTimeout(context.Background(), 15*time.Second)
	connectionB := dialAuthenticated(t, dialBCtx, servers[remoteB.Name], host.PublicNodeKey(), "token-b")
	dialBCancel()
	t.Cleanup(func() { _ = connectionB.Close() })
	assertPong(t, connectionA, "before-roam-a")
	assertPong(t, connectionB, "before-roam-b")

	oldGenerations := map[string]uint64{}
	oldDeliveries := map[string]uint64{}
	oldPorts := map[string]uint16{}
	for name, server := range servers {
		oldGenerations[name] = hub.EndpointGeneration(name)
		oldDeliveries[name] = hub.DeliveryCount(name)
		oldPorts[name] = server.Sys().MagicSock.Get().LocalPort()
		server.Sys().MagicSock.Get().RebindToNewPort()
		server.Sys().MagicSock.Get().ReSTUN("waifus-spike-mobility")
	}
	mobilityCtx, mobilityCancel := context.WithTimeout(context.Background(), 20*time.Second)
	waitForMobility(t, mobilityCtx, hub, servers, oldGenerations, oldDeliveries, oldPorts)
	mobilityCancel()
	probeDirectPath := func(server *tsnet.Server, viewer string, peerKey key.NodePublic) {
		pathCtx, pathCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer pathCancel()
		waitForDirectPath(t, pathCtx, hub, server, viewer, peerKey)
	}
	probeDirectPath(servers[remoteA.Name], remoteA.Name, host.PublicNodeKey())
	probeDirectPath(servers[remoteB.Name], remoteB.Name, host.PublicNodeKey())
	probeDirectPath(servers[host.Name], host.Name, remoteA.PublicNodeKey())
	probeDirectPath(servers[host.Name], host.Name, remoteB.PublicNodeKey())
	assertPong(t, connectionA, "after-roam-a")
	assertPong(t, connectionB, "after-roam-b")

	// Coordination is now unavailable. Host-local trust remains authoritative:
	// A is removed and its accepted stream is actively closed, while B's
	// existing and new streams continue without a B map update.
	hub.SetConnected(false)
	beforeBDeliveries := hub.DeliveryCount(remoteB.Name)
	if err := hub.DenyLocal(host.Name, remoteA.Name); err != nil {
		t.Fatalf("deny remote A locally: %v", err)
	}
	removed, err := servers[host.Name].RefreshWaifusPeerAuthorizations()
	if err != nil {
		t.Fatalf("refresh host authorizations: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed peers = %d, want 1", removed)
	}
	assertConnectionClosed(t, connectionA)
	assertPong(t, connectionB, "after-revoke-b")
	if got := hub.DeliveryCount(remoteB.Name); got != beforeBDeliveries {
		t.Fatalf("remote B map deliveries changed offline: got %d, want %d", got, beforeBDeliveries)
	}

	revokedCtx, revokedCancel := context.WithTimeout(context.Background(), 2*time.Second)
	newA, err := servers[remoteA.Name].DialWaifusPeer(revokedCtx, host.PublicNodeKey())
	revokedCancel()
	if err == nil {
		_ = newA.Close()
		t.Fatal("revoked remote A opened a new host stream")
	}
	newBCtx, newBCancel := context.WithTimeout(context.Background(), 15*time.Second)
	newB := dialAuthenticated(t, newBCtx, servers[remoteB.Name], host.PublicNodeKey(), "token-b")
	newBCancel()
	assertPong(t, newB, "new-after-revoke-b")
	_ = newB.Close()

	if err := hub.ProtocolError(); err != nil {
		t.Fatalf("fake-control protocol invariant: %v", err)
	}
	for name, server := range servers {
		counters := server.Sys().MagicSock.Get().DirectOnlyCounters()
		t.Logf("%s direct-only counters=%+v", name, counters)
		if counters.DERPAttempts != 0 || counters.PeerRelayAttempts != 0 ||
			counters.EgressAttempts != 0 || counters.IdentityMutationAttempts != 0 {
			t.Fatalf("%s prohibited-path counters = %+v, want all zero", name, counters)
		}
	}
}

func newSpikeServer(
	t *testing.T,
	hub *waifuscontrol.Hub,
	node waifuscontrol.Node,
	profile tsnet.WaifusControlProfile,
	controlURL string,
	stunEndpoint netip.AddrPort,
) *tsnet.Server {
	t.Helper()
	role := tsnet.WaifusNodeRoleRemote
	if node.Role == waifuscontrol.RoleHost {
		role = tsnet.WaifusNodeRoleHost
	}
	server := &tsnet.Server{
		Dir:       t.TempDir(),
		Store:     new(mem.Store),
		Ephemeral: true,
		Hostname:  node.Name,
		Logf:      logger.Discard,
		WaifusControl: &tsnet.WaifusControlConfig{
			Profile:         profile,
			Role:            role,
			ApplicationPort: spikeApplicationPort,
			STUNEndpoints:   []netip.AddrPort{stunEndpoint},
			NodePrivateKey:  node.NodePrivateKey,
			StableNodeID:    node.StableID,
			DiscoPrivateKey: node.DiscoPrivateKey,
			AuthorizePeer:   hub.Authorizer(node.Name),
			NewClient: func(gotProfile tsnet.WaifusControlProfile, opts controlclient.Options) (controlclient.Client, error) {
				if gotProfile != profile {
					return nil, fmt.Errorf("control profile = %d, want %d", gotProfile, profile)
				}
				if opts.ServerURL != controlURL {
					return nil, fmt.Errorf("control URL = %q, want %q", opts.ServerURL, controlURL)
				}
				return hub.NewClient(node.Name, opts)
			},
		},
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func spikeNode(name string, role waifuscontrol.Role, id tailcfg.NodeID, address string) waifuscontrol.Node {
	return waifuscontrol.Node{
		Name:            name,
		Role:            role,
		NodeID:          id,
		StableID:        tailcfg.StableNodeID(name),
		Address:         netip.MustParsePrefix(address),
		NodePrivateKey:  key.NewNode(),
		DiscoPrivateKey: key.NewDisco(),
	}
}

func mapHasDirectEndpoints(nm *netmap.NetworkMap) bool {
	if nm == nil || !nm.SelfNode.Valid() || nm.SelfNode.Endpoints().Len() == 0 {
		return false
	}
	for _, peer := range nm.Peers {
		if peer.Endpoints().Len() == 0 {
			return false
		}
	}
	return true
}

func assertPairIsolation(t *testing.T, hub *waifuscontrol.Hub, host, remoteA, remoteB waifuscontrol.Node) {
	t.Helper()
	hostMap := hub.LastMap(host.Name)
	if hostMap == nil || len(hostMap.Peers) != 2 {
		t.Fatalf("host map peers = %v, want two approved remotes", hostMap)
	}
	for _, pair := range []struct {
		viewer waifuscontrol.Node
		other  waifuscontrol.Node
	}{
		{viewer: remoteA, other: remoteB},
		{viewer: remoteB, other: remoteA},
	} {
		nm := hub.LastMap(pair.viewer.Name)
		if nm == nil || len(nm.Peers) != 1 || nm.Peers[0].Key() != host.PublicNodeKey() {
			t.Fatalf("%s map is not self plus host only: %v", pair.viewer.Name, nm)
		}
		if nodeFromMapOrZero(nm, pair.other.PublicNodeKey()).Valid() {
			t.Fatalf("%s learned %s's transport identity", pair.viewer.Name, pair.other.Name)
		}
	}
}

func nodeFromMap(t *testing.T, nm *netmap.NetworkMap, nodeKey key.NodePublic) tailcfg.NodeView {
	t.Helper()
	if node := nodeFromMapOrZero(nm, nodeKey); node.Valid() {
		return node
	}
	t.Fatalf("node %s absent from map", nodeKey.ShortString())
	return tailcfg.NodeView{}
}

func nodeFromMapOrZero(nm *netmap.NetworkMap, nodeKey key.NodePublic) tailcfg.NodeView {
	if nm == nil {
		return tailcfg.NodeView{}
	}
	if nm.SelfNode.Valid() && nm.SelfNode.Key() == nodeKey {
		return nm.SelfNode
	}
	for _, peer := range nm.Peers {
		if peer.Key() == nodeKey {
			return peer
		}
	}
	return tailcfg.NodeView{}
}

func waitForMobility(
	t *testing.T,
	ctx context.Context,
	hub *waifuscontrol.Hub,
	servers map[string]*tsnet.Server,
	oldGenerations map[string]uint64,
	oldDeliveries map[string]uint64,
	oldPorts map[string]uint16,
) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		allMoved := true
		for name, server := range servers {
			if hub.EndpointGeneration(name) <= oldGenerations[name] || hub.DeliveryCount(name) <= oldDeliveries[name] ||
				server.Sys().MagicSock.Get().LocalPort() == oldPorts[name] {
				allMoved = false
				break
			}
		}
		if allMoved {
			for name := range servers {
				if err := hub.WaitForMap(ctx, name, 1, mapHasDirectEndpoints); err != nil {
					t.Fatalf("wait for moved map %s: %v", name, err)
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for endpoint mobility: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForDirectPath(
	t *testing.T,
	ctx context.Context,
	hub *waifuscontrol.Hub,
	server *tsnet.Server,
	viewer string,
	peerKey key.NodePublic,
) {
	t.Helper()
	peer := nodeFromMap(t, hub.LastMap(viewer), peerKey)
	t.Logf("direct path probe %s -> %s endpoints=%v", viewer, peerKey.ShortString(), peer.Endpoints())
	result := new(ipnstate.PingResult)
	done := make(chan *ipnstate.PingResult, 1)
	if server == nil || server.Sys() == nil {
		t.Fatalf("direct path %s has no running server", viewer)
	}
	magicSock := server.Sys().MagicSock.Get()
	if magicSock == nil {
		t.Fatalf("direct path %s has no running magicsock", viewer)
	}
	magicSock.Ping(peer, result, 0, func(result *ipnstate.PingResult) {
		done <- result
	})
	select {
	case result := <-done:
		if result.Err != "" || result.Endpoint == "" {
			t.Fatalf("direct path %s -> %s failed: %+v", viewer, peerKey.ShortString(), result)
		}
	case <-ctx.Done():
		t.Fatalf("wait for direct path %s -> %s: %v", viewer, peerKey.ShortString(), ctx.Err())
	}
}

type authenticatedEchoServer struct {
	listener net.Listener
	tokens   map[string]string
	done     chan struct{}
	close    sync.Once
	wg       sync.WaitGroup
}

func newAuthenticatedEchoServer(listener net.Listener, tokens map[string]string) *authenticatedEchoServer {
	server := &authenticatedEchoServer{
		listener: listener,
		tokens:   tokens,
		done:     make(chan struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	return server
}

func (s *authenticatedEchoServer) Close() {
	s.close.Do(func() {
		close(s.done)
		_ = s.listener.Close()
	})
	s.wg.Wait()
}

func (s *authenticatedEchoServer) accept() {
	defer s.wg.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handle(connection)
	}
}

func (s *authenticatedEchoServer) handle(connection net.Conn) {
	defer s.wg.Done()
	defer connection.Close()
	reader := bufio.NewReader(connection)
	remoteHost, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil {
		return
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	wantToken, ok := s.tokens[remoteHost]
	if !ok || strings.TrimSpace(line) != "AUTH "+wantToken {
		_, _ = io.WriteString(connection, "DENIED\n")
		return
	}
	if _, err := io.WriteString(connection, "OK\n"); err != nil {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		message, ok := strings.CutPrefix(strings.TrimSpace(line), "PING ")
		if !ok {
			return
		}
		if _, err := fmt.Fprintf(connection, "PONG %s\n", message); err != nil {
			return
		}
	}
}

func dialAuthenticated(t *testing.T, ctx context.Context, server *tsnet.Server, peerKey key.NodePublic, token string) net.Conn {
	t.Helper()
	connection, err := server.DialWaifusPeer(ctx, peerKey)
	if err != nil {
		t.Fatalf("DialWaifusPeer: %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "AUTH %s\n", token); err != nil {
		t.Fatalf("write authentication: %v", err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("read authentication: %v", err)
	}
	if response != "OK\n" {
		t.Fatalf("authentication response = %q, want OK", response)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return connection
}

func assertPong(t *testing.T, connection net.Conn, message string) {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "PING %s\n", message); err != nil {
		t.Fatalf("write ping %q: %v", message, err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("read ping %q: %v", message, err)
	}
	if response != "PONG "+message+"\n" {
		t.Fatalf("ping %q response = %q", message, response)
	}
	_ = connection.SetDeadline(time.Time{})
}

func assertConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(connection, "PING revoked\n")
	if writeErr == nil {
		_, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr == nil {
			t.Fatal("revoked connection remained readable and writable")
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("revoked connection merely timed out instead of closing: %v", readErr)
		}
	}
}
