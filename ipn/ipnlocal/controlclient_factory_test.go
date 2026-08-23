// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

func TestControlClientFactoryConstructionOption(t *testing.T) {
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

	var calls int
	b, err := NewLocalBackend(
		logf,
		logid.PublicID{},
		sys,
		0,
		WithControlClientFactory(func(opts controlclient.Options) (controlclient.Client, error) {
			calls++
			return newClient(t, opts), nil
		}),
	)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)

	if err := b.Start(ipn.Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
}
