// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package magicsock

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/util/usermetric"
)

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
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	netMon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	t.Cleanup(func() { netMon.Close() })
	c, err := NewConn(Options{
		DirectOnly:             true,
		DisablePortMapper:      true,
		Logf:                   logger.Discard,
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		TestOnlyPacketListener: localhostListener{},
	})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
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
