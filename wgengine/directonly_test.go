// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package wgengine

import (
	"errors"
	"net/netip"
	"testing"

	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestDirectOnlyEngineRequiresNodeKey(t *testing.T) {
	engine, err := NewUserspaceEngine(logger.Discard, Config{DirectOnly: true})
	if engine != nil {
		engine.Close()
		t.Fatal("NewUserspaceEngine returned an engine without a node key")
	}
	if !errors.Is(err, ErrDirectOnlyNodeKey) {
		t.Fatalf("NewUserspaceEngine error = %v, want %v", err, ErrDirectOnlyNodeKey)
	}
}

func TestDirectOnlyEnginePinsNodeKeyAcrossReconfig(t *testing.T) {
	bus := eventbustest.NewBus(t)
	forced := key.NewNode()
	engine, err := NewUserspaceEngine(logger.Discard, Config{
		DirectOnly:         true,
		DirectSTUNEndpoint: netip.MustParseAddrPort("127.0.0.1:3478"),
		ForceNodeKey:       forced,
		ForceDiscoKey:      key.NewDisco(),
		HealthTracker:      health.NewTracker(bus),
		Metrics:            new(usermetric.Registry),
		EventBus:           bus,
	})
	if err != nil {
		t.Fatalf("NewUserspaceEngine: %v", err)
	}
	t.Cleanup(engine.Close)

	reconfigure := func(privateKey key.NodePrivate) error {
		return engine.Reconfig(
			&wgcfg.Config{PrivateKey: privateKey},
			&router.Config{},
			&dns.Config{},
		)
	}
	if err := reconfigure(forced); err != nil {
		t.Fatalf("install configured node key: %v", err)
	}
	if err := reconfigure(key.NewNode()); !errors.Is(err, ErrDirectOnlyNodeKey) {
		t.Fatalf("replacement node key error = %v, want %v", err, ErrDirectOnlyNodeKey)
	}
	if got := engine.(*userspaceEngine).lastCfg.PrivateKey; !got.Equal(forced) {
		t.Fatalf("node key after rejected reconfig changed")
	}
	if err := reconfigure(key.NodePrivate{}); err != nil {
		t.Fatalf("clear node key for stopped state: %v", err)
	}
	if err := reconfigure(forced); err != nil {
		t.Fatalf("restore configured node key: %v", err)
	}
	if got := engine.(*userspaceEngine).magicConn.DirectOnlyCounters().IdentityMutationAttempts; got != 1 {
		t.Fatalf("identity mutation attempts = %d, want 1", got)
	}
}
