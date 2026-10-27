// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/health"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
)

// recordingListener wraps a packet listener and, once armed, records every
// socket other than the main one (identified by its port): how many were
// opened and closed, and where each sent packets. With refuseExtra it refuses
// to open them, which reproduces a build that has only the main socket.
type recordingListener struct {
	inner       nettype.PacketListener
	armed       bool
	mainPort    uint16
	refuseExtra bool

	mu           sync.Mutex
	extraOpened  int
	extraClosed  int
	destinations map[netip.AddrPort]int
}

func (l *recordingListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	_, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	main := !l.armed || uint16(port) == l.mainPort
	l.mu.Unlock()
	if !main && l.refuseExtra {
		return nil, errors.New("extra sockets refused by test")
	}
	pc, err := l.inner.ListenPacket(ctx, network, address)
	if err != nil || main {
		return pc, err
	}
	l.mu.Lock()
	l.extraOpened++
	l.mu.Unlock()
	return &recordedConn{PacketConn: pc, listener: l}, nil
}

func (l *recordingListener) snapshot() (opened, closed int, destinations map[netip.AddrPort]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	destinations = make(map[netip.AddrPort]int, len(l.destinations))
	for destination, count := range l.destinations {
		destinations[destination] = count
	}
	return l.extraOpened, l.extraClosed, destinations
}

type recordedConn struct {
	net.PacketConn
	listener  *recordingListener
	closeOnce sync.Once
}

func (c *recordedConn) record(destination netip.AddrPort) {
	c.listener.mu.Lock()
	defer c.listener.mu.Unlock()
	if c.listener.destinations == nil {
		c.listener.destinations = make(map[netip.AddrPort]int)
	}
	c.listener.destinations[destination]++
}

func (c *recordedConn) WriteToUDPAddrPort(b []byte, destination netip.AddrPort) (int, error) {
	c.record(destination)
	return c.PacketConn.(nettype.PacketConn).WriteToUDPAddrPort(b, destination)
}

func (c *recordedConn) WriteTo(b []byte, destination net.Addr) (int, error) {
	if address, ok := destination.(*net.UDPAddr); ok {
		c.record(address.AddrPort())
	}
	return c.PacketConn.WriteTo(b, destination)
}

func (c *recordedConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return c.PacketConn.(nettype.PacketConn).ReadFromUDPAddrPort(b)
}

func (c *recordedConn) Close() error {
	c.closeOnce.Do(func() {
		c.listener.mu.Lock()
		c.listener.extraClosed++
		c.listener.mu.Unlock()
	})
	return c.PacketConn.Close()
}

func TestDirectOnlyNATPoolBoundExpiryAndReset(t *testing.T) {
	var pool directOnlyNATPool
	now := time.Unix(1_800_000_000, 0)
	generation, learn := pool.beginRefresh(now, "link-a")
	if !learn || generation == 0 {
		t.Fatalf("fresh pool generation=%d learn=%v, want a learning round", generation, learn)
	}
	// An unanswered round is not retried on every refresh.
	if _, learn := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval/2), "link-a"); learn {
		t.Fatal("an unanswered round was retried within the round interval")
	}
	if _, learn := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval), "link-a"); !learn {
		t.Fatal("an unanswered round was not retried after the round interval")
	}

	// Only public IPv4 addresses are remembered.
	pool.observe(now, generation, []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:41641"),
		netip.MustParseAddrPort("192.168.1.2:41641"),
		netip.MustParseAddrPort("100.64.0.1:41641"),
		netip.MustParseAddrPort("127.0.0.1:41641"),
		netip.MustParseAddrPort("[2001:db8::1]:41641"),
		netip.MustParseAddrPort("224.0.0.1:41641"),
	})
	if addrs, cross := pool.snapshot(now); len(addrs) != 0 || cross {
		t.Fatalf("non-public observations remembered: %v cross=%v", addrs, cross)
	}

	// The pool keeps the most recently observed addresses up to the bound.
	for index := range directOnlyNATPoolMax + 2 {
		at := now.Add(time.Duration(index) * time.Second)
		pool.observe(at, generation, []netip.AddrPort{
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(index + 1)}), uint16(40000+index)),
		})
	}
	addrs, cross := pool.snapshot(now.Add(time.Minute))
	if len(addrs) != directOnlyNATPoolMax || cross {
		t.Fatalf("pool = %v cross=%v, want %d addresses and no cross-address port", addrs, cross, directOnlyNATPoolMax)
	}
	if slices.Contains(addrs, netip.MustParseAddr("198.51.100.1")) || slices.Contains(addrs, netip.MustParseAddr("198.51.100.2")) {
		t.Fatalf("pool %v kept the oldest addresses instead of the newest", addrs)
	}

	pool.markLearned(generation)
	if _, learn := pool.beginRefresh(now.Add(2*time.Minute), "link-a"); learn {
		t.Fatal("a learned pool with fresh addresses asked for another round")
	}
	// An address unobserved for the relearn age asks for a refresh round
	// before it expires.
	if _, learn := pool.beginRefresh(now.Add(directOnlyNATPoolRelearnAge+time.Minute), "link-a"); !learn {
		t.Fatal("a stale remembered address did not ask for a learning round")
	}
	// Addresses unobserved for the lifetime expire.
	pool.observe(now.Add(directOnlyNATPoolLifetime), generation, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")})
	addrs, _ = pool.snapshot(now.Add(directOnlyNATPoolLifetime + 30*time.Second))
	if want := []netip.Addr{netip.MustParseAddr("203.0.113.9")}; !slices.Equal(addrs, want) {
		t.Fatalf("after expiry pool = %v, want %v", addrs, want)
	}

	// Two addresses on one port from one socket record the NAT keeping the
	// port across its addresses.
	pool.observe(now, generation, []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.177:50000"),
		netip.MustParseAddrPort("203.0.113.185:50000"),
	})
	if _, cross := pool.snapshot(now); !cross {
		t.Fatal("cross-address port evidence was not recorded")
	}

	// A network change clears everything and starts a new generation;
	// late observations from the old generation are discarded.
	newGeneration, learn := pool.beginRefresh(now, "link-b")
	if newGeneration == generation || !learn {
		t.Fatalf("link change generation=%d (was %d) learn=%v", newGeneration, generation, learn)
	}
	if addrs, cross := pool.snapshot(now); len(addrs) != 0 || cross {
		t.Fatalf("link change kept %v cross=%v", addrs, cross)
	}
	pool.observe(now, generation, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:41641")})
	pool.markLearned(generation)
	if addrs, _ := pool.snapshot(now); len(addrs) != 0 {
		t.Fatalf("stale-generation observation remembered: %v", addrs)
	}
	if _, learn := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval), "link-b"); !learn {
		t.Fatal("stale-generation answer marked the new network learned")
	}

	// An explicit reset (rebind, network down) also clears the pool.
	pool.observe(now, newGeneration, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:41641")})
	pool.markLearned(newGeneration)
	pool.reset()
	if addrs, _ := pool.snapshot(now); len(addrs) != 0 {
		t.Fatalf("reset kept %v", addrs)
	}
	if resetGeneration, learn := pool.beginRefresh(now, "link-b"); resetGeneration == newGeneration || !learn {
		t.Fatalf("after reset generation=%d learn=%v", resetGeneration, learn)
	}
}

func TestDirectOnlyPoolPort(t *testing.T) {
	report := func(addrs ...string) *netcheck.Report {
		r := &netcheck.Report{GlobalV4Counters: map[netip.AddrPort]int{}}
		for _, addr := range addrs {
			r.GlobalV4Counters[netip.MustParseAddrPort(addr)]++
		}
		return r
	}
	tests := []struct {
		name     string
		report   *netcheck.Report
		local    uint16
		cross    bool
		wantPort uint16
		wantOK   bool
	}{
		{name: "nil report"},
		{name: "no IPv4 observation", report: report(), local: 41641},
		{name: "port preserved", report: report("203.0.113.177:41641"), local: 41641, wantPort: 41641, wantOK: true},
		{name: "consistent unpreserved port without evidence", report: report("203.0.113.177:50000"), local: 41641},
		{name: "consistent port with cross-address evidence", report: report("203.0.113.177:50000"), local: 41641, cross: true, wantPort: 50000, wantOK: true},
		{name: "two addresses on one port", report: report("203.0.113.177:50000", "203.0.113.185:50000"), local: 41641, wantPort: 50000, wantOK: true},
		{name: "per-destination ports", report: report("203.0.113.177:41641", "203.0.113.177:50000"), local: 41641, cross: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, ok := directOnlyPoolPort(tt.report, tt.local, tt.cross)
			if port != tt.wantPort || ok != tt.wantOK {
				t.Fatalf("directOnlyPoolPort = %d, %v; want %d, %v", port, ok, tt.wantPort, tt.wantOK)
			}
		})
	}
}

// TestNATPoolUnusedOutsideDirectOnly checks that an ordinary build opens no
// extra sockets and derives no pool candidates while it STUNs.
func TestNATPoolUnusedOutsideDirectOnly(t *testing.T) {
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	netMon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer netMon.Close()
	stunAddr, stunCleanup := stuntest.Serve(t)
	defer stunCleanup()

	listener := &recordingListener{inner: localhostListener{}}
	endpoints := make(chan []tailcfg.Endpoint, 16)
	conn, err := NewConn(Options{
		DisablePortMapper:      true,
		Logf:                   logger.Discard,
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		TestOnlyPacketListener: listener,
		EndpointsFunc: func(eps []tailcfg.Endpoint) {
			select {
			case endpoints <- slices.Clone(eps):
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	listener.mu.Lock()
	listener.armed, listener.mainPort = true, conn.LocalPort()
	listener.mu.Unlock()

	conn.SetDERPMap(stuntest.DERPMapOf(stunAddr.String()))
	conn.SetPrivateKey(key.NewNode())
	go func() {
		buffers := [][]byte{make([]byte, 64<<10)}
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		receive := conn.receiveIPv4()
		for {
			if _, err := receive(buffers, sizes, eps); err != nil {
				return
			}
		}
	}()
	deadline := time.After(10 * time.Second)
	for stun := false; !stun; {
		select {
		case eps := <-endpoints:
			for _, ep := range eps {
				stun = stun || ep.Type == tailcfg.EndpointSTUN
			}
		case <-deadline:
			t.Fatal("no STUN endpoint")
		}
	}
	if opened, _, destinations := listener.snapshot(); opened != 0 || len(destinations) != 0 {
		t.Fatalf("ordinary build opened %d extra sockets sending to %v", opened, destinations)
	}
	if addrs, _ := conn.directOnlyNATPool.snapshot(time.Now()); len(addrs) != 0 {
		t.Fatalf("ordinary build remembered pool addresses %v", addrs)
	}
	if got := conn.directOnlyPoolEndpoints(&netcheck.Report{GlobalV4Counters: map[netip.AddrPort]int{
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), conn.LocalPort()): 1,
	}}); got != nil {
		t.Fatalf("ordinary build derived pool endpoints %v", got)
	}
	err = conn.sendDirectOnlyPoolProbe(nil, nil, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", stunAddr.Port)))
	if !errors.Is(err, ErrDirectOnlyEgress) {
		t.Fatalf("ordinary build pool probe send = %v, want ErrDirectOnlyEgress", err)
	}
}
