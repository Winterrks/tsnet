// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package tsnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

const waifusRestrictedApplicationPort uint16 = 43111

func TestWaifusControlRequiresRoleAndPeerAuthorizer(t *testing.T) {
	newClient := func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
		return &waifusTestControl{}, nil
	}

	s := &Server{WaifusControl: &WaifusControlConfig{NewClient: newClient}}
	if err := s.Start(); !errors.Is(err, ErrWaifusNodeRole) {
		t.Fatalf("missing role error = %v, want %v", err, ErrWaifusNodeRole)
	}

	s = &Server{WaifusControl: &WaifusControlConfig{
		Role:      WaifusNodeRoleRemote,
		NewClient: newClient,
	}}
	if err := s.Start(); !errors.Is(err, ErrWaifusPeerAuthorizerRequired) {
		t.Fatalf("missing authorizer error = %v, want %v", err, ErrWaifusPeerAuthorizerRequired)
	}

	s = &Server{WaifusControl: &WaifusControlConfig{
		Role:          WaifusNodeRoleRemote,
		AuthorizePeer: func(WaifusPeerIdentity) bool { return true },
		NewClient:     newClient,
	}}
	if err := s.Start(); !errors.Is(err, ErrWaifusApplicationPort) {
		t.Fatalf("missing application port error = %v, want %v", err, ErrWaifusApplicationPort)
	}

	s = &Server{WaifusControl: &WaifusControlConfig{
		Role:            WaifusNodeRoleRemote,
		ApplicationPort: waifusRestrictedApplicationPort,
		AuthorizePeer:   func(WaifusPeerIdentity) bool { return true },
		NewClient:       newClient,
	}}
	if err := s.Start(); !errors.Is(err, ErrWaifusSTUNEndpoint) {
		t.Fatalf("missing STUN endpoint error = %v, want %v", err, ErrWaifusSTUNEndpoint)
	}

	s = &Server{WaifusControl: &WaifusControlConfig{
		Role:            WaifusNodeRoleRemote,
		ApplicationPort: waifusRestrictedApplicationPort,
		STUNEndpoints:   []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")},
		AuthorizePeer:   func(WaifusPeerIdentity) bool { return true },
		NewClient:       newClient,
	}}
	if err := s.Start(); !errors.Is(err, ErrWaifusTransportIdentity) {
		t.Fatalf("missing transport identity error = %v, want %v", err, ErrWaifusTransportIdentity)
	}
}

func TestWaifusControlRejectsUnsafeSTUNEndpointBeforeInitialization(t *testing.T) {
	safe := netip.MustParseAddrPort("192.0.2.20:3478")
	tooMany := make([]netip.AddrPort, 0, magicsock.MaxDirectSTUNEndpoints+1)
	for index := range magicsock.MaxDirectSTUNEndpoints + 1 {
		tooMany = append(tooMany, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 3478))
	}
	tests := []struct {
		name      string
		endpoints []netip.AddrPort
	}{
		{name: "missing"},
		{name: "empty", endpoints: []netip.AddrPort{}},
		{name: "invalid", endpoints: []netip.AddrPort{{}}},
		{name: "zero port", endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:0")}},
		{name: "unspecified", endpoints: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:3478")}},
		{name: "multicast", endpoints: []netip.AddrPort{netip.MustParseAddrPort("224.0.0.1:3478")}},
		{name: "overlay", endpoints: []netip.AddrPort{netip.MustParseAddrPort("100.64.0.2:3478")}},
		{name: "DERP magic IP", endpoints: []netip.AddrPort{netip.MustParseAddrPort("127.3.3.40:3478")}},
		{name: "IPv4-mapped IPv6", endpoints: []netip.AddrPort{netip.MustParseAddrPort("[::ffff:192.0.2.10]:3478")}},
		{name: "unsafe after safe", endpoints: []netip.AddrPort{safe, netip.MustParseAddrPort("100.64.0.2:3478")}},
		{name: "duplicate", endpoints: []netip.AddrPort{safe, safe}},
		{name: "too many", endpoints: tooMany},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := waifusRestrictedTestConfig()
			config.STUNEndpoints = tt.endpoints
			s := &Server{WaifusControl: config}
			if err := s.Start(); !errors.Is(err, ErrWaifusSTUNEndpoint) {
				t.Fatalf("Start error = %v, want %v", err, ErrWaifusSTUNEndpoint)
			}
			if s.sys != nil || s.netMon != nil || s.shutdownCtx != nil {
				t.Fatal("unsafe STUN endpoint initialized server state")
			}
		})
	}
}

func TestWaifusControlRejectsGenericRuntimeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Server)
	}{
		{name: "auth key", mutate: func(s *Server) { s.AuthKey = "forbidden" }},
		{name: "OAuth secret", mutate: func(s *Server) { s.ClientSecret = "forbidden" }},
		{name: "workload client", mutate: func(s *Server) { s.ClientID = "forbidden" }},
		{name: "ID token", mutate: func(s *Server) { s.IDToken = "forbidden" }},
		{name: "audience", mutate: func(s *Server) { s.Audience = "forbidden" }},
		{name: "web client", mutate: func(s *Server) { s.RunWebClient = true }},
		{name: "ACL tags", mutate: func(s *Server) { s.AdvertiseTags = []string{"tag:forbidden"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{WaifusControl: waifusRestrictedTestConfig()}
			tt.mutate(s)
			if err := s.Start(); !errors.Is(err, ErrWaifusRuntimeConfiguration) {
				t.Fatalf("Start error = %v, want %v", err, ErrWaifusRuntimeConfiguration)
			}
			if s.sys != nil || s.netMon != nil || s.shutdownCtx != nil {
				t.Fatal("forbidden runtime configuration initialized server state")
			}
		})
	}
}

func TestWaifusControlRejectsCredentialEnvironment(t *testing.T) {
	for _, variable := range []string{
		"TS_AUTHKEY",
		"TS_AUTH_KEY",
		"TS_CLIENT_SECRET",
		"TS_CLIENT_ID",
		"TS_ID_TOKEN",
		"TS_AUDIENCE",
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
		"TS_DEBUG_PROXY_DNS",
		"TS_DEBUG_FAKE_PROXY_AUTH",
		"TS_DEBUG_USE_DERP_ADDR",
		"TS_DEBUG_USE_DERP_HTTP",
		"TS_DEBUG_ALWAYS_USE_DERP",
		"TS_DEBUG_PRETENDPOINT",
		"TS_DEBUG_SEND_CALLME_UNKNOWN_PEER",
	} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, "forbidden")
			s := &Server{WaifusControl: waifusRestrictedTestConfig()}
			if err := s.Start(); !errors.Is(err, ErrWaifusRuntimeConfiguration) {
				t.Fatalf("Start error = %v, want %v", err, ErrWaifusRuntimeConfiguration)
			}
		})
	}
}

func TestWaifusModeDisablesGenericTsnetSurfaces(t *testing.T) {
	s := &Server{WaifusControl: waifusRestrictedTestConfig()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Dial(ctx, "tcp", "100.64.0.2:80"); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("Dial error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.DialWaifusPeer(ctx, key.NodePublic{}); !errors.Is(err, ErrWaifusPeerUnavailable) {
		t.Fatalf("DialWaifusPeer zero-key error = %v, want %v", err, ErrWaifusPeerUnavailable)
	}
	if _, err := s.LocalClient(); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("LocalClient error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, _, _, err := s.Loopback(); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("Loopback error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.Up(ctx); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("Up error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.ListenPacket("udp", "100.64.0.1:1234"); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("ListenPacket error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.ListenSSH(":2222"); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("ListenSSH error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.ListenTLS("tcp", ":443"); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("ListenTLS error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
	if _, err := s.ListenFunnel("tcp", ":443"); !errors.Is(err, ErrWaifusOperationUnavailable) {
		t.Fatalf("ListenFunnel error = %v, want %v", err, ErrWaifusOperationUnavailable)
	}
}

func TestWaifusModeBuildsOnlyOneApplicationListener(t *testing.T) {
	s := &Server{
		Dir:           t.TempDir(),
		Store:         new(mem.Store),
		Ephemeral:     true,
		WaifusControl: waifusRestrictedTestConfig(),
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if s.localClient != nil || s.localAPIListener != nil || s.localAPIServer != nil {
		t.Fatal("Waifus mode constructed LocalAPI state")
	}
	if s.loopbackListener != nil || s.proxyCred != "" || s.localAPICred != "" {
		t.Fatal("Waifus mode constructed loopback proxy state")
	}
	if s.netstack.ProcessSubnets {
		t.Fatal("Waifus netstack enabled subnet processing")
	}
	if s.lb.ShouldRunSSH() || s.lb.ShouldRunWebClient() {
		t.Fatal("Waifus backend enabled SSH or web client")
	}

	first, err := s.Listen("tcp", ":43111")
	if err != nil {
		t.Fatalf("first application Listen: %v", err)
	}
	if _, err := s.Listen("tcp", ":43112"); !errors.Is(err, ErrWaifusApplicationListener) {
		t.Fatalf("second listener error = %v, want %v", err, ErrWaifusApplicationListener)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first listener: %v", err)
	}
	second, err := s.Listen("tcp", ":43111")
	if err != nil {
		t.Fatalf("reopen stable application listener: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second listener: %v", err)
	}
	if _, err := s.Listen("tcp", ":43112"); !errors.Is(err, ErrWaifusApplicationListener) {
		t.Fatalf("changed application port error = %v, want %v", err, ErrWaifusApplicationListener)
	}
}

func TestWaifusControlSnapshotsSTUNEndpointList(t *testing.T) {
	config := waifusRestrictedTestConfig()
	first := netip.MustParseAddrPort("192.0.2.30:3478")
	second := netip.MustParseAddrPort("198.51.100.30:19302")
	config.STUNEndpoints = []netip.AddrPort{first, second}
	s := &Server{WaifusControl: config}
	snapshot, err := s.snapshotWaifusControl()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	config.STUNEndpoints[0] = netip.MustParseAddrPort("203.0.113.30:3478")
	if want := []netip.AddrPort{first, second}; !slices.Equal(snapshot.stunEndpoints, want) {
		t.Fatalf("snapshot STUN endpoints = %v, want %v", snapshot.stunEndpoints, want)
	}
}

func waifusRestrictedTestConfig() *WaifusControlConfig {
	nodePrivate := key.NewNode()
	return &WaifusControlConfig{
		Role:            WaifusNodeRoleRemote,
		ApplicationPort: waifusRestrictedApplicationPort,
		STUNEndpoints:   []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")},
		NodePrivateKey:  nodePrivate,
		StableNodeID:    "restricted-test",
		DiscoPrivateKey: key.NewDisco(),
		AuthorizePeer: func(WaifusPeerIdentity) bool {
			return true
		},
		NewClient: func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
			return &waifusTestControl{}, nil
		},
	}
}
