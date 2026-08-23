// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package tsnet

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestWaifusControlRequiresFactoryBeforeInitialization(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "must-not-exist")
	s := &Server{
		Dir:           dir,
		WaifusControl: &WaifusControlConfig{},
	}

	err := s.Start()
	if !errors.Is(err, ErrWaifusControlClientFactoryRequired) {
		t.Fatalf("Start error = %v, want %v", err, ErrWaifusControlClientFactoryRequired)
	}
	if s.sys != nil || s.netMon != nil || s.shutdownCtx != nil {
		t.Fatal("missing-factory failure initialized network-facing server state")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state directory was created before validation: %v", err)
	}
}

func TestWaifusControlRejectsOriginOverrides(t *testing.T) {
	newClient := func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
		return &waifusTestControl{}, nil
	}

	t.Run("server field", func(t *testing.T) {
		s := &Server{
			ControlURL: "https://control.invalid.example",
			WaifusControl: &WaifusControlConfig{
				NewClient: newClient,
			},
		}
		err := s.Start()
		if !errors.Is(err, ErrWaifusControlURLOverride) {
			t.Fatalf("Start error = %v, want %v", err, ErrWaifusControlURLOverride)
		}
	})

	t.Run("environment", func(t *testing.T) {
		t.Setenv("TS_CONTROL_URL", "https://control.invalid.example")
		s := &Server{
			WaifusControl: &WaifusControlConfig{
				NewClient: newClient,
			},
		}
		err := s.Start()
		if !errors.Is(err, ErrWaifusControlURLOverride) {
			t.Fatalf("Start error = %v, want %v", err, ErrWaifusControlURLOverride)
		}
	})
}

func TestWaifusControlRejectsUnknownProfile(t *testing.T) {
	s := &Server{
		WaifusControl: &WaifusControlConfig{
			Profile: 99,
			NewClient: func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
				return &waifusTestControl{}, nil
			},
		},
	}
	err := s.Start()
	if !errors.Is(err, ErrWaifusControlProfile) {
		t.Fatalf("Start error = %v, want %v", err, ErrWaifusControlProfile)
	}
}

func TestWaifusControlFactoryIsPinnedForServerLifetime(t *testing.T) {
	tests := []struct {
		name       string
		configured WaifusControlProfile
		want       WaifusControlProfile
		wantURL    string
	}{
		{
			name:    "default production",
			want:    WaifusControlProduction,
			wantURL: waifusProductionControlURL,
		},
		{
			name:       "production",
			configured: WaifusControlProduction,
			want:       WaifusControlProduction,
			wantURL:    waifusProductionControlURL,
		},
		{
			name:       "staging",
			configured: WaifusControlStaging,
			want:       WaifusControlStaging,
			wantURL:    waifusStagingControlURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var clients []*waifusTestControl
			var profiles []WaifusControlProfile
			var serverURLs []string
			var replacementCalls int
			config := waifusRestrictedTestConfig()
			config.Profile = tt.configured
			config.NewClient = func(profile WaifusControlProfile, opts controlclient.Options) (controlclient.Client, error) {
				client := &waifusTestControl{shutdown: opts.Shutdown}
				clients = append(clients, client)
				profiles = append(profiles, profile)
				serverURLs = append(serverURLs, opts.ServerURL)
				return client, nil
			}

			s := &Server{
				Dir:           t.TempDir(),
				Store:         new(mem.Store),
				Ephemeral:     true,
				WaifusControl: config,
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					s.Close()
				}
			})

			if err := s.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}

			config.Profile = WaifusControlStaging
			config.NewClient = func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
				replacementCalls++
				return &waifusTestControl{}, nil
			}
			if err := s.lb.Start(ipn.Options{}); err != nil {
				t.Fatalf("second LocalBackend.Start: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			closed = true

			if replacementCalls != 0 {
				t.Fatalf("replacement factory calls = %d, want 0", replacementCalls)
			}
			if len(clients) != 2 {
				t.Fatalf("original factory calls = %d, want 2", len(clients))
			}
			for i, profile := range profiles {
				if profile != tt.want {
					t.Errorf("factory call %d profile = %d, want %d", i, profile, tt.want)
				}
			}
			for i, serverURL := range serverURLs {
				if serverURL != tt.wantURL {
					t.Errorf("factory call %d ServerURL = %q, want %q", i, serverURL, tt.wantURL)
				}
			}
			for i, client := range clients {
				if got := client.shutdownCount.Load(); got != 1 {
					t.Errorf("client %d Shutdown calls = %d, want 1", i, got)
				}
			}
		})
	}
}

func TestWaifusControlFactoryErrorHasNoStockFallback(t *testing.T) {
	wantErr := errors.New("custom factory sentinel")
	var calls int
	nodePrivate := key.NewNode()
	s := &Server{
		Dir:       t.TempDir(),
		Store:     new(mem.Store),
		Ephemeral: true,
		WaifusControl: &WaifusControlConfig{
			Role:            WaifusNodeRoleRemote,
			ApplicationPort: waifusRestrictedApplicationPort,
			STUNEndpoint:    netip.MustParseAddrPort("127.0.0.1:3478"),
			NodePrivateKey:  nodePrivate,
			StableNodeID:    "factory-error",
			DiscoPrivateKey: key.NewDisco(),
			AuthorizePeer:   func(WaifusPeerIdentity) bool { return true },
			NewClient: func(WaifusControlProfile, controlclient.Options) (controlclient.Client, error) {
				calls++
				return nil, wantErr
			},
		},
	}
	err := s.Start()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start error = %v, want wrapped %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("custom factory calls = %d, want 1", calls)
	}
}

type waifusTestControl struct {
	shutdown      func()
	shutdownOnce  sync.Once
	shutdownCount atomic.Int32
}

func (c *waifusTestControl) Shutdown() {
	c.shutdownCount.Add(1)
	c.shutdownOnce.Do(func() {
		if c.shutdown != nil {
			c.shutdown()
		}
	})
}

func (*waifusTestControl) Login(controlclient.LoginFlags)     {}
func (*waifusTestControl) Logout(context.Context) error       { return nil }
func (*waifusTestControl) SetPaused(bool)                     {}
func (*waifusTestControl) AuthCantContinue() bool             { return true }
func (*waifusTestControl) SetHostinfo(*tailcfg.Hostinfo)      {}
func (*waifusTestControl) SetNetInfo(*tailcfg.NetInfo)        {}
func (*waifusTestControl) SetTKAHead(string)                  {}
func (*waifusTestControl) UpdateEndpoints([]tailcfg.Endpoint) {}
func (*waifusTestControl) SetDiscoPublicKey(key.DiscoPublic)  {}
func (*waifusTestControl) SetIPForwardingBroken(bool)         {}
func (*waifusTestControl) ClientID() int64                    { return 1 }
