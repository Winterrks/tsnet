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

// poolObs builds one socket's observations: each pair is a STUN destination
// index and the mapping it reported.
func poolObs(pairs ...any) []directOnlyPoolObservation {
	var observations []directOnlyPoolObservation
	for index := 0; index < len(pairs); index += 2 {
		observations = append(observations, directOnlyPoolObservation{
			destination: netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, byte(pairs[index].(int))}), 3478),
			mapped:      netip.MustParseAddrPort(pairs[index+1].(string)),
		})
	}
	return observations
}

func TestDirectOnlyNATPoolAddress(t *testing.T) {
	for _, addr := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1",
		"192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.2", "198.18.0.1", "198.19.255.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "2001:4860::1",
	} {
		if directOnlyNATPoolAddress(netip.MustParseAddr(addr)) {
			t.Errorf("%s accepted as a NAT public address", addr)
		}
	}
	for _, addr := range []string{"1.0.0.4", "45.1.2.3", "194.65.90.177", "198.17.0.1", "198.20.0.1"} {
		if !directOnlyNATPoolAddress(netip.MustParseAddr(addr)) {
			t.Errorf("%s rejected as a NAT public address", addr)
		}
	}
}

func TestDirectOnlyNATPoolAdmitsOnlyAddressesTwoDestinationsReport(t *testing.T) {
	var pool directOnlyNATPool
	now := time.Unix(1_800_000_000, 0)
	generation, learn, remembered := pool.beginRefresh(now, "link-a")
	if !learn || generation == 0 || len(remembered) != 0 {
		t.Fatalf("fresh pool generation=%d learn=%v remembered=%v", generation, learn, remembered)
	}

	// One destination's report alone admits nothing, from any socket.
	pool.observe(now, generation, poolObs(1, "45.0.0.177:41641"))
	pool.observe(now, generation, poolObs(1, "45.0.0.177:50000"))
	if addrs, _ := pool.snapshot(now); len(addrs) != 0 {
		t.Fatalf("single-destination address admitted: %v", addrs)
	}
	// A second destination admits it, even from another socket and port.
	pool.observe(now, generation, poolObs(2, "45.0.0.177:51000"))
	if addrs, _ := pool.snapshot(now); !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("45.0.0.177")}) {
		t.Fatalf("pool = %v, want the twice-reported address", addrs)
	}

	// A lying destination forging a new address on the real port every
	// refresh never gets one admitted, cannot fake cross-address port
	// evidence, and cannot evict the real addresses.
	pool.observe(now, generation, poolObs(1, "45.0.0.185:41641", 2, "45.0.0.177:41641"))
	pool.observe(now, generation, poolObs(3, "45.0.0.185:41641"))
	for refresh := range 200 {
		at := now.Add(time.Duration(refresh) * time.Second)
		forged := netip.AddrPortFrom(netip.AddrFrom4([4]byte{46, 0, byte(refresh >> 8), byte(refresh)}), 41641)
		pool.observe(at, generation, []directOnlyPoolObservation{
			{destination: netip.MustParseAddrPort("9.9.9.4:3478"), mapped: forged},
			{destination: netip.MustParseAddrPort("9.9.9.1:3478"), mapped: netip.MustParseAddrPort("45.0.0.177:41641")},
		})
	}
	addrs, cross := pool.snapshot(now.Add(200 * time.Second))
	if want := []netip.Addr{netip.MustParseAddr("45.0.0.177"), netip.MustParseAddr("45.0.0.185")}; !slices.Equal(addrs, want) {
		t.Fatalf("pool after forged refreshes = %v, want %v", addrs, want)
	}
	if !cross {
		t.Fatal("the real cross-address port evidence was lost")
	}
	pool.mu.Lock()
	tracked := len(pool.entries)
	pool.mu.Unlock()
	if tracked > directOnlyNATPoolTracked {
		t.Fatalf("pool tracks %d entries, want at most %d", tracked, directOnlyNATPoolTracked)
	}

	// Cross-address port evidence needs both addresses admitted.
	var other directOnlyNATPool
	otherGeneration, _, _ := other.beginRefresh(now, "link-a")
	other.observe(now, otherGeneration, poolObs(1, "45.0.0.177:41641", 2, "45.0.0.177:41641"))
	other.observe(now, otherGeneration, poolObs(3, "46.0.0.1:41641", 1, "45.0.0.177:41641"))
	if _, cross := other.snapshot(now); cross {
		t.Fatal("a forged address on the real port produced cross-address port evidence")
	}
}

func TestDirectOnlyNATPoolBoundExpiryAndReset(t *testing.T) {
	var pool directOnlyNATPool
	now := time.Unix(1_800_000_000, 0)
	generation, _, _ := pool.beginRefresh(now, "link-a")
	// An unanswered round is not retried on every refresh.
	if _, learn, _ := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval/2), "link-a"); learn {
		t.Fatal("an unanswered round was retried within the round interval")
	}
	if _, learn, _ := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval), "link-a"); !learn {
		t.Fatal("an unanswered round was not retried after the round interval")
	}

	// The pool admits at most the most recently observed addresses.
	for index := range directOnlyNATPoolMax + 2 {
		at := now.Add(time.Duration(index) * time.Second)
		mapped := fmt.Sprintf("45.0.1.%d:41641", index+1)
		pool.observe(at, generation, poolObs(1, mapped, 2, mapped))
	}
	addrs, cross := pool.snapshot(now.Add(time.Minute))
	if len(addrs) != directOnlyNATPoolMax || cross {
		t.Fatalf("pool = %v cross=%v, want %d addresses and no cross-address port", addrs, cross, directOnlyNATPoolMax)
	}
	if slices.Contains(addrs, netip.MustParseAddr("45.0.1.1")) || slices.Contains(addrs, netip.MustParseAddr("45.0.1.2")) {
		t.Fatalf("pool %v kept the oldest addresses instead of the newest", addrs)
	}

	pool.markLearned(generation)
	if _, learn, _ := pool.beginRefresh(now.Add(2*time.Minute), "link-a"); learn {
		t.Fatal("a learned pool with fresh addresses asked for another round")
	}
	// An address unobserved for the relearn age asks for a refresh round
	// before it expires.
	if _, learn, _ := pool.beginRefresh(now.Add(directOnlyNATPoolRelearnAge+time.Minute), "link-a"); !learn {
		t.Fatal("a stale remembered address did not ask for a learning round")
	}
	// Addresses unobserved for the lifetime expire.
	pool.observe(now.Add(directOnlyNATPoolLifetime), generation, poolObs(1, "45.0.2.9:41641", 2, "45.0.2.9:41641"))
	addrs, _ = pool.snapshot(now.Add(directOnlyNATPoolLifetime + 30*time.Second))
	if want := []netip.Addr{netip.MustParseAddr("45.0.2.9")}; !slices.Equal(addrs, want) {
		t.Fatalf("after expiry pool = %v, want %v", addrs, want)
	}

	// A network change clears everything and starts a new generation;
	// late observations from the old generation are discarded.
	newGeneration, learn, remembered := pool.beginRefresh(now, "link-b")
	if newGeneration == generation || !learn || len(remembered) != 0 {
		t.Fatalf("link change generation=%d (was %d) learn=%v remembered=%v", newGeneration, generation, learn, remembered)
	}
	pool.observe(now, generation, poolObs(1, "45.0.3.1:41641", 2, "45.0.3.1:41641"))
	pool.markLearned(generation)
	if addrs, _ := pool.snapshot(now); len(addrs) != 0 {
		t.Fatalf("stale-generation observation remembered: %v", addrs)
	}
	if _, learn, _ := pool.beginRefresh(now.Add(directOnlyPoolRoundInterval), "link-b"); !learn {
		t.Fatal("stale-generation answer marked the new network learned")
	}

	// An explicit reset (rebind, network down) also clears the pool.
	pool.observe(now, newGeneration, poolObs(1, "45.0.3.2:41641", 2, "45.0.3.2:41641"))
	pool.markLearned(newGeneration)
	pool.reset()
	if addrs, _ := pool.snapshot(now); len(addrs) != 0 {
		t.Fatalf("reset kept %v", addrs)
	}
	if resetGeneration, learn, _ := pool.beginRefresh(now, "link-b"); resetGeneration == newGeneration || !learn {
		t.Fatalf("after reset generation=%d learn=%v", resetGeneration, learn)
	}
}

// TestDirectOnlyNATPoolResetsOnUnrelatedMainReport covers a network change
// that keeps the interface and local address (so no rebind and no new link
// fingerprint): a main-socket report sharing no address with the remembered
// pool clears it.
func TestDirectOnlyNATPoolResetsOnUnrelatedMainReport(t *testing.T) {
	var pool directOnlyNATPool
	now := time.Unix(1_800_000_000, 0)
	generation, _, _ := pool.beginRefresh(now, "link-a")
	pool.observe(now, generation, poolObs(1, "45.0.0.177:41641", 2, "45.0.0.185:41641"))
	pool.observe(now, generation, poolObs(1, "45.0.0.185:41641", 2, "45.0.0.177:41641"))
	pool.markLearned(generation)

	next, _, remembered := pool.beginRefresh(now.Add(time.Minute), "link-a")
	if next != generation || len(remembered) != 2 {
		t.Fatalf("refresh generation=%d remembered=%v", next, remembered)
	}
	// A report that still sees one remembered address keeps the pool.
	if got, reset := pool.resetIfUnrelated(next, poolObs(1, "45.0.0.185:41641", 2, "47.0.0.1:41641"), remembered); reset || got != next {
		t.Fatalf("related report reset the pool (generation %d, reset %v)", got, reset)
	}
	// A report without IPv4 observations decides nothing.
	if _, reset := pool.resetIfUnrelated(next, nil, remembered); reset {
		t.Fatal("an empty report reset the pool")
	}
	// A report sharing no address clears it and needs a new round.
	got, reset := pool.resetIfUnrelated(next, poolObs(1, "47.0.0.1:41641", 2, "47.0.0.1:41641"), remembered)
	if !reset || got == next {
		t.Fatalf("unrelated report kept the pool (generation %d, reset %v)", got, reset)
	}
	if addrs, _ := pool.snapshot(now.Add(time.Minute)); len(addrs) != 0 {
		t.Fatalf("pool after unrelated report = %v", addrs)
	}
	if _, learn, _ := pool.beginRefresh(now.Add(time.Minute), "link-a"); !learn {
		t.Fatal("unrelated report did not schedule a learning round")
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
	admitted := []netip.Addr{netip.MustParseAddr("45.0.0.177"), netip.MustParseAddr("45.0.0.185")}
	tests := []struct {
		name     string
		report   *netcheck.Report
		local    uint16
		cross    bool
		admitted []netip.Addr
		wantPort uint16
		wantOK   bool
	}{
		{name: "nil report"},
		{name: "no IPv4 observation", report: report(), local: 41641, admitted: admitted},
		{name: "port preserved", report: report("45.0.0.177:41641"), local: 41641, admitted: admitted, wantPort: 41641, wantOK: true},
		{name: "port preserved but address not admitted", report: report("45.0.0.177:41641"), local: 41641},
		{name: "consistent unpreserved port without evidence", report: report("45.0.0.177:50000"), local: 41641, admitted: admitted},
		{name: "consistent port with cross-address evidence", report: report("45.0.0.177:50000"), local: 41641, cross: true, admitted: admitted, wantPort: 50000, wantOK: true},
		// Two addresses on one port in a report are evidence only once the
		// pool has admitted both (the cross flag).
		{name: "two addresses on one port without admitted evidence", report: report("45.0.0.177:50000", "45.0.0.185:50000"), local: 41641, admitted: admitted},
		{name: "per-destination ports", report: report("45.0.0.177:41641", "45.0.0.185:50000"), local: 41641, cross: true, admitted: admitted},
		// A single destination's odd-port answer for an unadmitted address
		// neither forges a port nor disables the pool.
		{name: "unadmitted odd-port observation ignored", report: report("45.0.0.177:41641", "46.0.0.1:50000"), local: 41641, admitted: admitted, wantPort: 41641, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, ok := directOnlyPoolPort(tt.report, tt.local, tt.cross, tt.admitted)
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
		netip.AddrPortFrom(netip.MustParseAddr("45.0.0.1"), conn.LocalPort()): 1,
	}}); got != nil {
		t.Fatalf("ordinary build derived pool endpoints %v", got)
	}
	err = conn.sendDirectOnlyPoolProbe(nil, nil, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", stunAddr.Port)))
	if !errors.Is(err, ErrDirectOnlyEgress) {
		t.Fatalf("ordinary build pool probe send = %v, want ErrDirectOnlyEgress", err)
	}
}
