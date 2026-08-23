// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"go4.org/netipx"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

const waifusTestApplicationPort uint16 = 43111

func TestWaifusNetworkMapValidatorAcceptsPairIsolatedViews(t *testing.T) {
	tests := []struct {
		name      string
		role      WaifusNodeRole
		peerCount int
	}{
		{name: "remote without selected host", role: WaifusNodeRoleRemote},
		{name: "remote with selected host", role: WaifusNodeRoleRemote, peerCount: 1},
		{name: "host without remotes", role: WaifusNodeRoleHost},
		{name: "host with independently approved remotes", role: WaifusNodeRoleHost, peerCount: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm := validWaifusNetworkMap(tt.peerCount)
			validator, err := newWaifusNetworkMapValidator(tt.role, waifusTestApplicationPort, func(WaifusPeerIdentity) bool { return true })
			if err != nil {
				t.Fatalf("newWaifusNetworkMapValidator: %v", err)
			}
			if err := validator.Validate(nm); err != nil {
				t.Fatalf("Validate valid pair view: %v", err)
			}
		})
	}
}

func TestWaifusNetworkMapValidatorRejectsGenericTailnetState(t *testing.T) {
	tests := []struct {
		name   string
		role   WaifusNodeRole
		mutate func(*netmap.NetworkMap)
	}{
		{
			name: "cached map",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				nm.Cached = true
			},
		},
		{
			name: "map machine key",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				nm.MachineKey = key.NewMachine().Public()
			},
		},
		{
			name: "remote receives another remote",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				nm.Peers = append(nm.Peers, waifusTestNode(3, "100.64.0.3/32").View())
			},
		},
		{
			name: "host receives unapproved remote",
			role: WaifusNodeRoleHost,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Key = key.NewNode().Public()
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "peer presence",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				online := true
				n.Online = &online
				n.LastSeen = new(time.Time)
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "generic owner metadata",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Name = "forbidden.example."
				n.User = 1
				n.Machine = key.NewMachine().Public()
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "host metadata",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{Hostname: "forbidden"}).View()
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "DERP map",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				nm.DERPMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1}}}
			},
		},
		{
			name: "DERP home",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.HomeDERP = 1
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "peer relay",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{PeerRelay: true}).View()
				nm.Peers[0] = n.View()
			},
		},
		{
			name:   "DNS",
			role:   WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) { nm.DNS.Proxied = true },
		},
		{
			name: "subnet and exit route",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "OS route",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
				nm.Peers[0] = n.View()
			},
		},
		{
			name:   "SSH policy",
			role:   WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) { nm.SSHPolicy = new(tailcfg.SSHPolicy) },
		},
		{
			name:   "control packet filter",
			role:   WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) { nm.PacketFilter = []filter.Match{{}} },
		},
		{
			name:   "service collection",
			role:   WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) { nm.CollectServices = true },
		},
		{
			name: "service capability",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.SelfNode.AsStruct()
				n.CapMap = tailcfg.NodeCapMap{"waifus.invalid/service": nil}
				nm.SelfNode = n.View()
			},
		},
		{
			name: "arbitrary and peer API services",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{Services: []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 1}, {Proto: tailcfg.TCP, Port: 443}}}).View()
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "unsigned peer API only",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.UnsignedPeerAPIOnly = true
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "route advertisement",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.SelfNode.AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}).View()
				nm.SelfNode = n.View()
			},
		},
		{
			name: "app connector",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.SelfNode.AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{AppConnector: opt.NewBool(true)}).View()
				nm.SelfNode = n.View()
			},
		},
		{
			name: "remote configuration and auto-update",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.SelfNode.AsStruct()
				n.Hostinfo = (&tailcfg.Hostinfo{RemoteConfig: true, AllowsUpdate: true}).View()
				nm.SelfNode = n.View()
			},
		},
		{
			name: "key expiry and rotation",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.KeyExpiry = time.Now().Add(time.Hour)
				nm.Peers[0] = n.View()
			},
		},
		{
			name: "relay endpoint",
			role: WaifusNodeRoleRemote,
			mutate: func(nm *netmap.NetworkMap) {
				n := nm.Peers[0].AsStruct()
				n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
				nm.Peers[0] = n.View()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm := validWaifusNetworkMap(1)
			approvedKey := nm.Peers[0].Key()
			validator, err := newWaifusNetworkMapValidator(tt.role, waifusTestApplicationPort, func(identity WaifusPeerIdentity) bool {
				return identity.NodeKey == approvedKey
			})
			if err != nil {
				t.Fatalf("newWaifusNetworkMapValidator: %v", err)
			}
			tt.mutate(nm)
			if err := validator.Validate(nm); !errors.Is(err, ErrWaifusNetworkMap) {
				t.Fatalf("Validate error = %v, want %v", err, ErrWaifusNetworkMap)
			}
		})
	}
}

func TestWaifusNetworkMapValidatorPinsIdentityAndAddress(t *testing.T) {
	nm := validWaifusNetworkMap(1)
	validator, err := newWaifusNetworkMapValidator(WaifusNodeRoleRemote, waifusTestApplicationPort, func(WaifusPeerIdentity) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(nm); err != nil {
		t.Fatalf("initial Validate: %v", err)
	}

	changedAddress := &netmap.NetworkMap{
		SelfNode: nm.SelfNode,
		NodeKey:  nm.NodeKey,
		Peers:    append([]tailcfg.NodeView(nil), nm.Peers...),
	}
	changedPeer := changedAddress.Peers[0].AsStruct()
	changedPeer.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.99/32")}
	changedPeer.AllowedIPs = append([]netip.Prefix(nil), changedPeer.Addresses...)
	changedAddress.Peers[0] = changedPeer.View()
	if err := validator.Validate(changedAddress); !errors.Is(err, ErrWaifusNetworkMap) {
		t.Fatalf("changed address error = %v, want %v", err, ErrWaifusNetworkMap)
	}

	changedDisco := &netmap.NetworkMap{
		SelfNode: nm.SelfNode,
		NodeKey:  nm.NodeKey,
		Peers:    append([]tailcfg.NodeView(nil), nm.Peers...),
	}
	changedPeer = changedDisco.Peers[0].AsStruct()
	changedPeer.DiscoKey = key.NewDisco().Public()
	changedDisco.Peers[0] = changedPeer.View()
	if err := validator.Validate(changedDisco); !errors.Is(err, ErrWaifusNetworkMap) {
		t.Fatalf("changed disco key error = %v, want %v", err, ErrWaifusNetworkMap)
	}

	reusedPeer := waifusTestNode(99, "100.64.0.99/32")
	reusedPeer.ID = nm.Peers[0].ID()
	reusedPeer.StableID = nm.Peers[0].StableID()
	reusedStableIdentity := &netmap.NetworkMap{
		SelfNode: nm.SelfNode,
		NodeKey:  nm.NodeKey,
		Peers:    []tailcfg.NodeView{reusedPeer.View()},
	}
	if err := validator.Validate(reusedStableIdentity); !errors.Is(err, ErrWaifusNetworkMap) {
		t.Fatalf("reused stable identity error = %v, want %v", err, ErrWaifusNetworkMap)
	}
}

func TestWaifusNetworkMapRejectedBeforeBackendMutation(t *testing.T) {
	logf := logger.Discard
	bus := eventbustest.NewBus(t)
	sys := tsd.NewSystemWithBus(bus)
	sys.Set(new(mem.Store))
	engine, err := wgengine.NewFakeUserspaceEngine(
		logf,
		sys.Set,
		sys.HealthTracker.Get(),
		sys.UserMetricsRegistry(),
		sys.Bus.Get(),
	)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(engine.Close)
	sys.Set(engine)

	var client *mockControl
	approved := true
	b, err := NewLocalBackend(
		logf,
		logid.PublicID{},
		sys,
		0,
		WithControlClientFactory(func(opts controlclient.Options) (controlclient.Client, error) {
			client = newClient(t, opts)
			return client, nil
		}),
		WithWaifusNetworkMapPolicy(WaifusNodeRoleRemote, waifusTestApplicationPort, func(WaifusPeerIdentity) bool { return approved }),
	)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)
	if err := b.Start(ipn.Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	invalid := validWaifusNetworkMap(1)
	invalid.DNS.Proxied = true
	client.send(sendOpt{nm: invalid, loginFinished: true})

	if got := b.NetMap(); got != nil {
		t.Fatal("forbidden map was installed in LocalBackend")
	}
	if err := b.WaifusNetworkMapError(); !errors.Is(err, ErrWaifusNetworkMap) {
		t.Fatalf("WaifusNetworkMapError = %v, want %v", err, ErrWaifusNetworkMap)
	}
	if !b.isEngineBlocked() {
		t.Fatal("engine remained enabled after a forbidden map")
	}

	valid := validWaifusNetworkMap(1)
	client.send(sendOpt{nm: valid, loginFinished: true})
	if got := b.NetMap(); got == nil {
		t.Fatal("valid pair-only map was not installed")
	}
	if err := b.WaifusNetworkMapError(); err != nil {
		t.Fatalf("WaifusNetworkMapError after recovery = %v, want nil", err)
	}
	if b.isEngineBlocked() {
		t.Fatal("engine remained blocked after a valid logged-in pair map")
	}
	peerKey := valid.Peers[0].Key()
	peerAddress, ok := b.WaifusPeerAddress(peerKey)
	if !ok || peerAddress != valid.Peers[0].Addresses().At(0).Addr() {
		t.Fatalf("WaifusPeerAddress = %v, %v; want %v, true", peerAddress, ok, valid.Peers[0].Addresses().At(0).Addr())
	}
	if _, ok := b.WaifusPeerAddress(key.NewNode().Public()); ok {
		t.Fatal("WaifusPeerAddress resolved a peer outside the installed map")
	}
	approved = false
	if _, ok := b.WaifusPeerAddress(peerKey); ok {
		t.Fatal("WaifusPeerAddress resolved a dynamically revoked peer")
	}
}

func TestWaifusPacketFilterAllowsOnlyApprovedPeerToSelfTCP(t *testing.T) {
	nm := validWaifusNetworkMap(1)
	var localNets netipx.IPSetBuilder
	localNets.AddPrefix(nm.SelfNode.Addresses().At(0))
	localSet, err := localNets.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	filt := filter.New(waifusPacketFilter(nm, waifusTestApplicationPort), nil, localSet, nil, nil, logger.Discard)
	self := nm.SelfNode.Addresses().At(0).Addr()
	peer := nm.Peers[0].Addresses().At(0).Addr()

	tests := []struct {
		name  string
		src   netip.Addr
		dst   netip.Addr
		port  uint16
		proto ipproto.Proto
		want  filter.Response
	}{
		{name: "approved peer TCP application port", src: peer, dst: self, port: waifusTestApplicationPort, proto: ipproto.TCP, want: filter.Accept},
		{name: "approved peer TCP wrong port", src: peer, dst: self, port: waifusTestApplicationPort + 1, proto: ipproto.TCP, want: filter.Drop},
		{name: "approved peer UDP", src: peer, dst: self, port: waifusTestApplicationPort, proto: ipproto.UDP, want: filter.Drop},
		{name: "unapproved source", src: netip.MustParseAddr("100.64.0.99"), dst: self, port: waifusTestApplicationPort, proto: ipproto.TCP, want: filter.Drop},
		{name: "cross-peer destination", src: self, dst: peer, port: waifusTestApplicationPort, proto: ipproto.TCP, want: filter.Drop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filt.Check(tt.src, tt.dst, tt.port, tt.proto); got != tt.want {
				t.Fatalf("filter response = %v, want %v", got, tt.want)
			}
		})
	}
}

func validWaifusNetworkMap(peerCount int) *netmap.NetworkMap {
	self := waifusTestNode(1, "100.64.0.1/32")
	nm := &netmap.NetworkMap{
		SelfNode: self.View(),
		NodeKey:  self.Key,
	}
	for i := 0; i < peerCount; i++ {
		peer := waifusTestNode(tailcfg.NodeID(i+2), "100.64.0."+string(rune('2'+i))+"/32")
		peer.Endpoints = []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:41641"),
			netip.MustParseAddrPort("[2001:db8::10]:41641"),
		}
		nm.Peers = append(nm.Peers, peer.View())
	}
	return nm
}

func waifusTestNode(id tailcfg.NodeID, address string) *tailcfg.Node {
	prefix := netip.MustParsePrefix(address)
	return &tailcfg.Node{
		ID:                id,
		StableID:          tailcfg.StableNodeID("waifus-" + address),
		Key:               key.NewNode().Public(),
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{prefix},
		AllowedIPs:        []netip.Prefix{prefix},
		MachineAuthorized: true,
		Cap:               tailcfg.CurrentCapabilityVersion,
	}
}
