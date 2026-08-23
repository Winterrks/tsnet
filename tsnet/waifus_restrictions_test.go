// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package tsnet

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/key"
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
		STUNEndpoint:    netip.MustParseAddrPort("127.0.0.1:3478"),
		AuthorizePeer:   func(WaifusPeerIdentity) bool { return true },
		NewClient:       newClient,
	}}
	if err := s.Start(); !errors.Is(err, ErrWaifusTransportIdentity) {
		t.Fatalf("missing transport identity error = %v, want %v", err, ErrWaifusTransportIdentity)
	}
}

func TestWaifusControlRejectsUnsafeSTUNEndpointBeforeInitialization(t *testing.T) {
	tests := []struct {
		name     string
		endpoint netip.AddrPort
	}{
		{name: "missing"},
		{name: "zero port", endpoint: netip.MustParseAddrPort("192.0.2.10:0")},
		{name: "unspecified", endpoint: netip.MustParseAddrPort("0.0.0.0:3478")},
		{name: "multicast", endpoint: netip.MustParseAddrPort("224.0.0.1:3478")},
		{name: "overlay", endpoint: netip.MustParseAddrPort("100.64.0.2:3478")},
		{name: "DERP magic IP", endpoint: netip.MustParseAddrPort("127.3.3.40:3478")},
		{name: "IPv4-mapped IPv6", endpoint: netip.MustParseAddrPort("[::ffff:192.0.2.10]:3478")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := waifusRestrictedTestConfig()
			config.STUNEndpoint = tt.endpoint
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

func waifusRestrictedTestConfig() *WaifusControlConfig {
	nodePrivate := key.NewNode()
	return &WaifusControlConfig{
		Role:            WaifusNodeRoleRemote,
		ApplicationPort: waifusRestrictedApplicationPort,
		STUNEndpoint:    netip.MustParseAddrPort("127.0.0.1:3478"),
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
