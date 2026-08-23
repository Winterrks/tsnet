// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !waifus_direct_only

package tsnet

import (
	"errors"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/wgengine"
)

func TestWaifusControlRequiresDirectOnlyBuild(t *testing.T) {
	var factoryCalls int
	s := &Server{
		Dir:       t.TempDir(),
		Store:     new(mem.Store),
		Ephemeral: true,
		WaifusControl: &WaifusControlConfig{
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
