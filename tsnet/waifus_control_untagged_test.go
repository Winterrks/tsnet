// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !waifus_direct_only

package tsnet

import (
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
)

func TestWaifusControlRequiresDirectOnlyBuild(t *testing.T) {
	var factoryCalls int
	nodePrivate := key.NewNode()
	s := &Server{
		Dir:       t.TempDir(),
		Store:     new(mem.Store),
		Ephemeral: true,
		WaifusControl: &WaifusControlConfig{
			Role:            WaifusNodeRoleRemote,
			ApplicationPort: 43111,
			STUNEndpoint:    netip.MustParseAddrPort("127.0.0.1:3478"),
			NodePrivateKey:  nodePrivate,
			StableNodeID:    "untagged-test",
			DiscoPrivateKey: key.NewDisco(),
			AuthorizePeer:   func(WaifusPeerIdentity) bool { return true },
			NewClient: func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
				factoryCalls++
				return nil, errors.New("factory must not run")
			},
		},
	}
	err := s.Start()
	if !errors.Is(err, wgengine.ErrDirectOnlyBuildRequired) {
		t.Fatalf("Start error = %v, want %v", err, wgengine.ErrDirectOnlyBuildRequired)
	}
	if factoryCalls != 0 {
		t.Fatalf("control factory calls = %d, want 0", factoryCalls)
	}
}
