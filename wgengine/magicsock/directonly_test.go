// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package magicsock

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/util/usermetric"
)

func TestDirectOnlyRequiresConfiguredSTUNEndpoint(t *testing.T) {
	safe := netip.MustParseAddrPort("192.0.2.10:3478")
	tooMany := make([]netip.AddrPort, 0, MaxDirectSTUNEndpoints+1)
	for index := range MaxDirectSTUNEndpoints + 1 {
		tooMany = append(tooMany, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 3478))
	}
	for name, endpoints := range map[string][]netip.AddrPort{
		"missing":       nil,
		"empty":         {},
		"invalid":       {{}},
		"unsafe member": {safe, netip.MustParseAddrPort("100.64.0.2:3478")},
		"duplicate":     {safe, safe},
		"too many":      tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			opts := directOnlyTestOptions(t)
			opts.DirectSTUNEndpoints = endpoints
			if _, err := NewConn(opts); !errors.Is(err, ErrDirectOnlySTUNEndpoint) {
				t.Fatalf("NewConn error = %v, want %v", err, ErrDirectOnlySTUNEndpoint)
			}
		})
	}
	t.Run("ordinary mode", func(t *testing.T) {
		opts := directOnlyTestOptions(t)
		opts.DirectOnly = false
		opts.ForceNodeKey = key.NodePrivate{}
		if c, err := NewConn(opts); err == nil {
			c.Close()
			t.Fatal("ordinary Conn accepted direct-only STUN endpoints")
		}
	})
}

func TestDirectOnlyCopiesSTUNEndpointList(t *testing.T) {
	first := netip.MustParseAddrPort("127.0.0.1:3478")
	second := netip.MustParseAddrPort("127.0.0.1:19302")
	opts := directOnlyTestOptions(t)
	opts.DirectSTUNEndpoints = []netip.AddrPort{first, second}
	c, err := NewConn(opts)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	opts.DirectSTUNEndpoints[0] = netip.MustParseAddrPort("127.0.0.1:9")
	if !c.directOnlySTUNEndpointAllowed(first) || !c.directOnlySTUNEndpointAllowed(second) {
		t.Fatal("configured STUN endpoints changed after the caller mutated its slice")
	}
	if _, err := c.sendUDPNetcheck([]byte("forbidden"), netip.MustParseAddrPort("127.0.0.1:9")); !errors.Is(err, ErrDirectOnlyEgress) {
		t.Fatalf("sendUDPNetcheck to caller-mutated destination error = %v, want %v", err, ErrDirectOnlyEgress)
	}
}

func TestDirectOnlyRequiresConfiguredDiscoveryKey(t *testing.T) {
	opts := directOnlyTestOptions(t)
	opts.ForceDiscoKey = key.DiscoPrivate{}
	if _, err := NewConn(opts); !errors.Is(err, ErrDirectOnlyDiscoKey) {
		t.Fatalf("NewConn error = %v, want %v", err, ErrDirectOnlyDiscoKey)
	}
}

func TestDirectOnlyRequiresConfiguredNodeKey(t *testing.T) {
	opts := directOnlyTestOptions(t)
	opts.ForceNodeKey = key.NodePrivate{}
	if _, err := NewConn(opts); !errors.Is(err, ErrDirectOnlyNodeKey) {
		t.Fatalf("NewConn error = %v, want %v", err, ErrDirectOnlyNodeKey)
	}
}

func TestDirectOnlyPinsForcedNodeKey(t *testing.T) {
	opts := directOnlyTestOptions(t)
	forced := opts.ForceNodeKey
	c, err := NewConn(opts)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetPrivateKey(forced); err != nil {
		t.Fatalf("install configured node key: %v", err)
	}
	if err := c.SetPrivateKey(key.NewNode()); !errors.Is(err, ErrDirectOnlyNodeKey) {
		t.Fatalf("replacement node key error = %v, want %v", err, ErrDirectOnlyNodeKey)
	}
	if got := c.publicKeyAtomic.Load(); got != forced.Public() {
		t.Fatalf("node key after replacement attempt = %v, want %v", got, forced.Public())
	}
	if err := c.SetPrivateKey(key.NodePrivate{}); err != nil {
		t.Fatalf("temporarily clear node key: %v", err)
	}
	if err := c.SetPrivateKey(forced); err != nil {
		t.Fatalf("restore configured node key: %v", err)
	}
	if got := c.DirectOnlyCounters().IdentityMutationAttempts; got != 1 {
		t.Fatalf("identity mutation attempts = %d, want 1", got)
	}
}

func TestDirectOnlyPinsForcedDiscoveryKey(t *testing.T) {
	forced := key.NewDisco()
	opts := directOnlyTestOptions(t)
	opts.ForceDiscoKey = forced
	c, err := NewConn(opts)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if got := c.DiscoPublicKey(); got != forced.Public() {
		t.Fatalf("initial discovery key = %v, want configured key %v", got, forced.Public())
	}
	c.RotateDiscoKey()
	if got := c.DiscoPublicKey(); got != forced.Public() {
		t.Fatalf("discovery key after rotation attempt = %v, want pinned key %v", got, forced.Public())
	}
	if got := c.DirectOnlyCounters().IdentityMutationAttempts; got != 1 {
		t.Fatalf("identity mutation attempts = %d, want 1", got)
	}
}

func TestDirectOnlySTUNUsesOnlyConfiguredDestinationsWithoutDERP(t *testing.T) {
	var stunEndpoints []netip.AddrPort
	for range 2 {
		stunAddr, cleanup := stuntest.Serve(t)
		t.Cleanup(cleanup)
		stunEndpoints = append(stunEndpoints, netip.MustParseAddrPort(stunAddr.String()))
	}
	c := newDirectOnlySTUNTestConn(t, stunEndpoints)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := c.updateNetInfo(ctx)
	if err != nil {
		t.Fatalf("updateNetInfo: %v", err)
	}
	if !report.UDP {
		t.Fatal("configured STUN endpoints did not produce a UDP report")
	}
	if len(report.RegionLatency) != len(stunEndpoints) {
		t.Fatalf("STUN regions answered = %v, want all %d configured destinations", report.RegionLatency, len(stunEndpoints))
	}
	if c.derpMap != nil || c.derpMapAtomic.Load() != nil {
		t.Fatal("direct-only STUN installed a DERP map")
	}

	forbidden := netip.AddrPortFrom(stunEndpoints[0].Addr(), stunEndpoints[0].Port()+1)
	for slices.Contains(stunEndpoints, forbidden) {
		forbidden = netip.AddrPortFrom(forbidden.Addr(), forbidden.Port()+1)
	}
	if _, err := c.sendUDPNetcheck([]byte("forbidden"), forbidden); !errors.Is(err, ErrDirectOnlyEgress) {
		t.Fatalf("sendUDPNetcheck error = %v, want %v", err, ErrDirectOnlyEgress)
	}
	if got := c.DirectOnlyCounters(); got != (DirectOnlyCounters{EgressAttempts: 1}) {
		t.Fatalf("direct-only counters = %+v, want exactly one prohibited egress attempt", got)
	}
}

// TestDirectOnlyAdvertisesEveryPerDestinationPublicAddress models a NAT that
// preserves the mapped port but picks the public IPv4 address per destination
// from a pool. Each address is seen by only one STUN destination, so upstream
// GetGlobalAddrs would keep just the first; direct-only must advertise all of
// them, on every refresh, without touching any non-configured destination.
func TestDirectOnlyAdvertisesEveryPerDestinationPublicAddress(t *testing.T) {
	const mappedPort = 41641
	mapped := []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.177"), mappedPort),
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.185"), mappedPort),
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.190"), mappedPort),
		// A hard-NAT style singular mapping on another port stays excluded.
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.200"), mappedPort+1),
	}
	var stunEndpoints []netip.AddrPort
	for _, value := range mapped {
		stunEndpoints = append(stunEndpoints, serveMappedSTUN(t, value))
	}
	c := newDirectOnlySTUNTestConn(t, stunEndpoints)

	// The second report would be incremental, and probe only the fastest
	// three regions, without direct-only's every-destination policy.
	for round := range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		endpoints, err := c.determineEndpoints(ctx)
		cancel()
		if err != nil {
			t.Fatalf("round %d determineEndpoints: %v", round, err)
		}
		var stun []netip.AddrPort
		for _, endpoint := range endpoints {
			if endpoint.Type == tailcfg.EndpointSTUN {
				stun = append(stun, endpoint.Addr)
			}
		}
		slices.SortFunc(stun, netip.AddrPort.Compare)
		// The first responder is always kept; whichever destination that is,
		// all three same-port addresses must be present. The different-port
		// mapping may appear only if it happened to be the first responder.
		for _, want := range mapped[:3] {
			if !slices.Contains(stun, want) {
				t.Fatalf("round %d STUN endpoints = %v, missing per-destination address %v", round, stun, want)
			}
		}
		if len(stun) != 3 && !(len(stun) == 4 && slices.Contains(stun, mapped[3])) {
			t.Fatalf("round %d STUN endpoints = %v, want exactly the three same-port addresses", round, stun)
		}
		// Endpoint caching could mask a skipped destination, so also
		// require that this round's own report heard from every one.
		report := c.lastNetCheckReport.Load()
		if report == nil || len(report.RegionLatency) != len(stunEndpoints) {
			t.Fatalf("round %d report = %+v, want answers from all %d destinations", round, report, len(stunEndpoints))
		}
		if got := c.DirectOnlyCounters(); got != (DirectOnlyCounters{}) {
			t.Fatalf("round %d direct-only counters = %+v, want zero", round, got)
		}
	}
}

func newDirectOnlySTUNTestConn(t *testing.T, stunEndpoints []netip.AddrPort) *Conn {
	t.Helper()
	opts := directOnlyTestOptions(t)
	opts.DirectSTUNEndpoints = stunEndpoints
	c, err := NewConn(opts)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	receiveFuncs, _, err := c.bind.Open(0)
	if err != nil {
		t.Fatalf("bind.Open: %v", err)
	}
	go func() {
		packets := [][]byte{make([]byte, 64<<10)}
		sizes := make([]int, 1)
		endpoints := make([]conn.Endpoint, 1)
		for {
			if _, err := receiveFuncs[0](packets, sizes, endpoints); err != nil {
				return
			}
		}
	}()
	return c
}

// serveMappedSTUN runs a loopback STUN responder that reports mapped as the
// requester's server-reflexive address.
func serveMappedSTUN(t *testing.T, mapped netip.AddrPort) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen STUN responder: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			txID, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			_, _ = pc.WriteToUDPAddrPort(stun.Response(txID, mapped), src)
		}
	}()
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestDirectOnlyAdvertisesLocalEndpointsWithoutSTUN(t *testing.T) {
	t.Setenv("IN_TS_TEST", "")
	c := newDirectOnlyTestConn(t)
	local := []tailcfg.Endpoint{{
		Addr: netip.MustParseAddrPort("192.0.2.10:41641"),
		Type: tailcfg.EndpointLocal,
	}}
	if !c.setEndpoints(local) {
		t.Fatal("direct-only local endpoint update was suppressed while no DERP map was installed")
	}
	if len(c.lastEndpoints) != 1 || c.lastEndpoints[0] != local[0] {
		t.Fatalf("stored endpoints = %v, want %v", c.lastEndpoints, local)
	}
}

func TestDirectOnlyKeepsApprovedSTUNCandidatesFreshWhileIdle(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkNetworkUpDuringTests = true
	c.privateKey = key.NewNode()
	c.peersByID = map[tailcfg.NodeID]tailcfg.NodeView{1: directOnlyTestNode(1, 0, false, "100.64.0.2/32")}
	c.idleFunc = func() time.Duration { return time.Hour }
	if !c.shouldDoPeriodicReSTUNLocked() {
		t.Fatal("direct-only discovery stopped during idle with an authorized peer and no DERP wake-up path")
	}
	c.networkUp.Store(false)
	if c.shouldDoPeriodicReSTUNLocked() {
		t.Fatal("offline connection kept STUN active")
	}
	c.networkUp.Store(true)
	privateKey := c.privateKey
	c.privateKey = key.NodePrivate{}
	if c.shouldDoPeriodicReSTUNLocked() {
		t.Fatal("keyless connection kept STUN active")
	}
	c.privateKey = privateKey
	peers := c.peersByID
	c.peersByID = nil
	if c.shouldDoPeriodicReSTUNLocked() {
		t.Fatal("unpaired connection kept STUN active")
	}
	c.peersByID = peers
	c.directOnly = false
	if c.shouldDoPeriodicReSTUNLocked() {
		t.Fatal("ordinary Tailscale idle behavior changed")
	}
	c.directOnly = true
}

func TestDirectOnlyPeriodicDiscoveryRetriesIdlePeer(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
	peer := directOnlyTestNode(2, 0, false, "100.64.0.2/32")
	if err := c.SetNetworkMap(self, []tailcfg.NodeView{peer}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.privateKey = c.directOnlyNodeKey
	c.checkNetworkUpDuringTests = true
	c.networkUp.Store(true)
	ep, ok := c.peerMap.endpointForNodeKey(peer.Key())
	if !ok {
		c.mu.Unlock()
		t.Fatal("missing authorized peer")
	}
	ep.mu.Lock()
	ep.lastFullPing = 0
	ep.mu.Unlock()
	c.mu.Unlock()
	c.doPeriodicSTUN()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.lastFullPing.IsZero() {
		t.Fatal("idle peer was not reprobed by periodic discovery")
	}
	if !ep.lastSendExt.IsZero() {
		t.Fatal("periodic discovery pretended to be application traffic")
	}
}

func TestDirectOnlyPeriodicDiscoverySendsRateLimitedDirectPacket(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	c := newDirectOnlyTestConn(t)
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPrivateKey(c.directOnlyNodeKey); err != nil {
		t.Fatal(err)
	}
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
	peerNode := directOnlyTestNode(2, 0, false, "100.64.0.2/32").AsStruct()
	address := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	peerNode.Endpoints = []netip.AddrPort{address}
	peer := peerNode.View()
	if err := c.SetNetworkMap(self, []tailcfg.NodeView{peer}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	readProbe := func() {
		t.Helper()
		sink.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := sink.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(buffer[:n], []byte(disco.Magic)) {
			t.Fatal("not an encrypted direct discovery packet")
		}
	}
	readProbe()
	c.mu.Lock()
	ep, _ := c.peerMap.endpointForNodeKey(peer.Key())
	ep.mu.Lock()
	ep.endpointState[address].lastPing = mono.Now().Add(-discoPingInterval)
	ep.mu.Unlock()
	c.mu.Unlock()
	c.doPeriodicSTUN()
	readProbe()
	c.doPeriodicSTUN()
	sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := sink.ReadFromUDPAddrPort(buffer); err == nil {
		t.Fatal("immediate retry bypassed per-endpoint rate limit")
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("forbidden transport attempted: %+v", counters)
	}
}

func TestDirectOnlyPeriodicDiscoveryStopsOutsideAuthorizedOnlineSession(t *testing.T) {
	for _, mode := range []string{"ordinary", "offline", "keyless", "homeless", "expired", "removed", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c := newDirectOnlyTestConn(t)
			self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
			peer := directOnlyTestNode(2, 0, false, "100.64.0.2/32")
			if err := c.SetNetworkMap(self, []tailcfg.NodeView{peer}); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			c.privateKey = c.directOnlyNodeKey
			c.checkNetworkUpDuringTests = true
			c.networkUp.Store(true)
			ep, _ := c.peerMap.endpointForNodeKey(peer.Key())
			ep.mu.Lock()
			ep.lastFullPing = 0
			if mode == "expired" {
				ep.expired = true
			}
			ep.mu.Unlock()
			switch mode {
			case "ordinary":
				c.directOnly = false
			case "offline":
				c.networkUp.Store(false)
			case "keyless":
				c.privateKey = key.NodePrivate{}
			case "homeless":
				c.homeless = true
			}
			c.mu.Unlock()
			if mode == "removed" {
				if err := c.SetNetworkMap(self, nil); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed" {
				c.Close()
			}
			c.doPeriodicSTUN()
			ep.mu.Lock()
			probed := !ep.lastFullPing.IsZero()
			ep.mu.Unlock()
			c.mu.Lock()
			c.directOnly = true
			c.mu.Unlock()
			if probed {
				t.Fatal("periodic discovery probed an ineligible peer")
			}
		})
	}
}

func TestDirectOnlyRebindToNewPortPreservesRandomPortPolicy(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatalf("bind.Open: %v", err)
	}
	oldPort := c.LocalPort()
	if oldPort == 0 {
		t.Fatal("initial direct-only UDP port is zero")
	}
	for range 5 {
		c.RebindToNewPort()
		if c.LocalPort() != oldPort {
			break
		}
	}
	if got := c.LocalPort(); got == 0 || got == oldPort {
		t.Fatalf("rebound UDP port = %d, want fresh non-zero port distinct from %d", got, oldPort)
	}
	if preferred := c.port.Load(); preferred != 0 {
		t.Fatalf("random-port rebind changed preferred port to %d", preferred)
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("direct rebind changed prohibited counters: %+v", counters)
	}
}

func TestDirectOnlyRejectsDERPBeforeInstallOrSend(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {RegionID: 1},
		},
	}
	if err := c.SetDERPMap(dm); !errors.Is(err, ErrDirectOnlyDERPMap) {
		t.Fatalf("SetDERPMap error = %v, want %v", err, ErrDirectOnlyDERPMap)
	}
	if c.derpMap != nil || c.derpMapAtomic.Load() != nil {
		t.Fatal("rejected DERP map was installed")
	}

	derpAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)
	sent, err := c.sendAddr(derpAddr, key.NewNode().Public(), []byte("forbidden"), false, false)
	if sent || !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("sendAddr = (%v, %v), want (false, %v)", sent, err, ErrNoDirectPath)
	}
	if ch := c.derpWriteChanForRegion(1, key.NodePublic{}); ch != nil {
		t.Fatal("direct-only DERP writer returned a channel")
	}
	if len(c.activeDerp) != 0 {
		t.Fatalf("active DERP connections = %d, want 0", len(c.activeDerp))
	}

	counters := c.DirectOnlyCounters()
	if counters.DERPAttempts != 3 {
		t.Fatalf("DERP attempts = %d, want 3", counters.DERPAttempts)
	}
}

func TestDirectOnlyIgnoresDebugDERPOverride(t *testing.T) {
	if os.Getenv("WAIFUS_DEBUG_DERP_CHILD") == "" {
		command := exec.Command(os.Args[0], "-test.run=^TestDirectOnlyIgnoresDebugDERPOverride$", "-test.count=1")
		command.Env = append(os.Environ(),
			"WAIFUS_DEBUG_DERP_CHILD=1",
			"TS_DEBUG_USE_DERP_ADDR=127.0.0.1",
			"TS_DEBUG_USE_DERP_HTTP=true",
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("debug-DERP child failed: %v\n%s", err, output)
		}
		return
	}
	c := newDirectOnlyTestConn(t)
	if err := c.SetDERPMap(nil); err != nil {
		t.Fatalf("SetDERPMap(nil): %v", err)
	}
	if c.derpMap != nil || c.derpMapAtomic.Load() != nil {
		t.Fatal("debug environment installed a DERP map in direct-only mode")
	}
}

func TestDirectOnlyRejectsPeerRelayBeforeManagerOrSend(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	relayServers := make(set.Set[candidatePeerRelay])
	relayServers.Add(candidatePeerRelay{
		nodeKey:  key.NewNode().Public(),
		discoKey: key.NewDisco().Public(),
	})
	c.relayManager.handleRelayServersSet(relayServers)
	if c.relayManager.startDiscoveryCh != nil || c.relayManager.runLoopStoppedCh != nil {
		t.Fatal("direct-only relay manager was initialized")
	}

	sent, err := c.sendUDP(netip.MustParseAddrPort("127.0.0.1:9"), []byte("forbidden"), false, true)
	if sent || !errors.Is(err, ErrDirectOnlyPeerRelay) {
		t.Fatalf("peer-relay send = (%v, %v), want (false, %v)", sent, err, ErrDirectOnlyPeerRelay)
	}

	counters := c.DirectOnlyCounters()
	if counters.PeerRelayAttempts != 2 {
		t.Fatalf("peer-relay attempts = %d, want 2", counters.PeerRelayAttempts)
	}
}

func TestDirectOnlyRejectsRelayFieldsWithoutMutatingPeers(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")

	tests := []struct {
		name string
		peer tailcfg.NodeView
	}{
		{
			name: "DERP home",
			peer: directOnlyTestNode(2, 7, false, "100.64.0.2/32"),
		},
		{
			name: "peer relay server",
			peer: directOnlyTestNode(2, 0, true, "100.64.0.2/32"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := c.SetNetworkMap(self, []tailcfg.NodeView{tt.peer}); !errors.Is(err, ErrDirectOnlyRelayConfiguration) {
				t.Fatalf("SetNetworkMap error = %v, want %v", err, ErrDirectOnlyRelayConfiguration)
			}
			if err := c.UpsertPeer(tt.peer); !errors.Is(err, ErrDirectOnlyRelayConfiguration) {
				t.Fatalf("UpsertPeer error = %v, want %v", err, ErrDirectOnlyRelayConfiguration)
			}
			c.mu.Lock()
			peerCount := len(c.peersByID)
			c.mu.Unlock()
			if peerCount != 0 {
				t.Fatalf("installed peers after rejection = %d, want 0", peerCount)
			}
		})
	}
}

func TestDirectOnlyPathSelectorReturnsOnlyDirectAddresses(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
	peer := directOnlyTestNode(2, 0, false, "100.64.0.2/32")
	if err := c.SetNetworkMap(self, []tailcfg.NodeView{peer}); err != nil {
		t.Fatalf("SetNetworkMap with direct-only nodes: %v", err)
	}
	if c.relayManager.startDiscoveryCh != nil || c.relayManager.runLoopStoppedCh != nil {
		t.Fatal("valid direct-only map initialized relay manager")
	}

	now := mono.Now()
	for _, addr := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:41641"),
		netip.MustParseAddrPort("[2001:db8::10]:41641"),
	} {
		de := &endpoint{
			c:                  c,
			bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
			trustBestAddrUntil: now.Add(time.Minute),
		}
		udpAddr, derpAddr, _ := de.addrForSendLocked(now)
		if udpAddr.ap != addr || udpAddr.vni.IsSet() {
			t.Errorf("selected UDP address = %v, want direct %v", udpAddr, addr)
		}
		if derpAddr.IsValid() {
			t.Errorf("selected forbidden DERP address %v", derpAddr)
		}
	}

	de := &endpoint{
		c:                 c,
		heartbeatDisabled: true,
		isWireguardOnly:   true,
		endpointState:     map[netip.AddrPort]*endpointState{},
	}
	if err := de.send(nil, 0); !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("send with no direct endpoint error = %v, want %v", err, ErrNoDirectPath)
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("valid direct/no-path operations changed prohibited counters: %+v", counters)
	}
}

func TestDirectOnlyBindExcludesDERPReceive(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	receiveFuncs, _, err := c.bind.Open(0)
	if err != nil {
		t.Fatalf("bind.Open: %v", err)
	}
	if len(receiveFuncs) != 2 {
		t.Fatalf("direct-only receive functions = %d, want IPv4 and IPv6 only", len(receiveFuncs))
	}
	if err := c.bind.Close(); err != nil {
		t.Fatalf("bind.Close: %v", err)
	}
	select {
	case <-c.derpRecvCh:
		t.Fatal("direct-only bind close wrote to the DERP receive queue")
	default:
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("direct-only bind lifecycle changed prohibited counters: %+v", counters)
	}
}

func TestDirectOnlyDropsGeneveAtUDPIngress(t *testing.T) {
	c := newDirectOnlyTestConn(t)
	pkt := make([]byte, packet.GeneveFixedHeaderLength+4)
	header := packet.GeneveHeader{Protocol: packet.GeneveProtocolWireGuard}
	header.VNI.Set(1)
	if err := header.Encode(pkt); err != nil {
		t.Fatalf("encode Geneve packet: %v", err)
	}

	ep, size, encapsulated, ok := c.receiveIP(
		pkt,
		netip.MustParseAddrPort("127.0.0.1:41641"),
		new(epAddrEndpointCache),
	)
	if ep != nil || size != 0 || encapsulated || ok {
		t.Fatalf("receiveIP accepted Geneve packet: endpoint=%v size=%d encapsulated=%v ok=%v", ep, size, encapsulated, ok)
	}
	if counters := c.DirectOnlyCounters(); counters.PeerRelayAttempts != 1 || counters.DERPAttempts != 0 {
		t.Fatalf("prohibited counters after Geneve ingress = %+v, want one peer-relay attempt", counters)
	}
}

func newDirectOnlyTestConn(t *testing.T) *Conn {
	t.Helper()
	c, err := NewConn(directOnlyTestOptions(t))
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func directOnlyTestOptions(t *testing.T) Options {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	netMon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	t.Cleanup(func() { netMon.Close() })
	return Options{
		DirectOnly:             true,
		DirectSTUNEndpoints:    []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")},
		ForceNodeKey:           key.NewNode(),
		ForceDiscoKey:          key.NewDisco(),
		DisablePortMapper:      true,
		Logf:                   logger.Discard,
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		TestOnlyPacketListener: localhostListener{},
	}
}

func directOnlyTestNode(id tailcfg.NodeID, homeDERP int, peerRelay bool, prefix string) tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:        id,
		Key:       key.NewNode().Public(),
		DiscoKey:  key.NewDisco().Public(),
		Addresses: []netip.Prefix{netip.MustParsePrefix(prefix)},
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix(prefix),
		},
		HomeDERP: homeDERP,
		Hostinfo: (&tailcfg.Hostinfo{PeerRelay: peerRelay}).View(),
		Cap:      tailcfg.CurrentCapabilityVersion,
	}).View()
}
