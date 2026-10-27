// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab"
	"tailscale.com/types/nettype"
)

// directOnlyPoolNAT is a natlab NAT that keeps each socket's local port and
// chooses the public IPv4 address per destination from a pool, sticky per
// socket and destination, with address-and-port dependent filtering per
// public address. This is the shape measured on a real Wi-Fi network: two
// public addresses, one socket seeing only one of them on every STUN server
// while its traffic to the peer leaves through the other.
//
// The main socket (mainPort) takes mainChoice for each destination. Every
// other socket takes the pool addresses round-robin per destination, starting
// after the main socket's choice, so that a learning round observes the pool
// deterministically.
type directOnlyPoolNAT struct {
	lan        *natlab.Interface
	wan        []*natlab.Interface
	mainPort   uint16
	mainChoice func(dst netip.AddrPort) int

	mu            sync.Mutex
	choice        map[[2]netip.AddrPort]int           // (LAN source, destination) -> pool index
	extraMappings map[netip.AddrPort]int              // destination -> non-main mappings so far
	lanByWAN      map[netip.AddrPort]netip.AddrPort   // public source -> LAN source
	open          map[[2]netip.AddrPort]bool          // (public source, remote) opened by outbound traffic
	usedByDst     map[netip.AddrPort]map[int]struct{} // destination -> pool indexes used
}

func (n *directOnlyPoolNAT) isWAN(addr netip.Addr) bool {
	for _, wan := range n.wan {
		if wan.V4() == addr {
			return true
		}
	}
	return false
}

func (n *directOnlyPoolNAT) pickLocked(src, dst netip.AddrPort) int {
	first := 0
	if n.mainChoice != nil {
		first = n.mainChoice(dst) % len(n.wan)
	}
	if src.Port() == n.mainPort {
		return first
	}
	n.extraMappings[dst]++
	return (first + n.extraMappings[dst]) % len(n.wan)
}

func (n *directOnlyPoolNAT) HandleOut(p *natlab.Packet, oif *natlab.Interface) *natlab.Packet {
	return p
}

func (n *directOnlyPoolNAT) HandleIn(p *natlab.Packet, iif *natlab.Interface) *natlab.Packet {
	if !n.isWAN(p.Dst.Addr()) {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	lanSource, ok := n.lanByWAN[p.Dst]
	if !ok || !n.open[[2]netip.AddrPort{p.Dst, p.Src}] {
		return nil
	}
	p.Dst = lanSource
	return p
}

func (n *directOnlyPoolNAT) HandleForward(p *natlab.Packet, iif, oif *natlab.Interface) *natlab.Packet {
	if iif != n.lan {
		if oif == n.lan {
			// Already admitted and translated by HandleIn.
			return p
		}
		return nil
	}
	if n.isWAN(p.Src.Addr()) {
		// Already translated; retraversing forwarding.
		return p
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.choice == nil {
		n.choice = make(map[[2]netip.AddrPort]int)
		n.extraMappings = make(map[netip.AddrPort]int)
		n.lanByWAN = make(map[netip.AddrPort]netip.AddrPort)
		n.open = make(map[[2]netip.AddrPort]bool)
		n.usedByDst = make(map[netip.AddrPort]map[int]struct{})
	}
	key := [2]netip.AddrPort{p.Src, p.Dst}
	index, ok := n.choice[key]
	if !ok {
		index = n.pickLocked(p.Src, p.Dst)
		n.choice[key] = index
		if n.usedByDst[p.Dst] == nil {
			n.usedByDst[p.Dst] = make(map[int]struct{})
		}
		n.usedByDst[p.Dst][index] = struct{}{}
	}
	public := netip.AddrPortFrom(n.wan[index].V4(), p.Src.Port())
	n.lanByWAN[public] = p.Src
	n.open[[2]netip.AddrPort{public, p.Dst}] = true
	p.Src = public
	return p
}

// mainSocketChoice reports the pool address the main socket uses toward dst.
func (n *directOnlyPoolNAT) mainSocketChoice(dst netip.AddrPort) netip.Addr {
	return n.wan[n.mainChoice(dst)%len(n.wan)].V4()
}

const directOnlyPoolLabRemotePort = 41641

// forgingSTUN is a lying STUN server: it answers every binding request with
// a new forged public address on the requester's real mapped port.
type forgingSTUN struct {
	mu     sync.Mutex
	forged []netip.AddrPort
}

func (f *forgingSTUN) serve(t *testing.T, machine *natlab.Machine, iface *natlab.Interface) netip.AddrPort {
	t.Helper()
	pc, err := machine.ListenPacket(context.Background(), "udp4", ":3478")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	conn := pc.(nettype.PacketConn)
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, source, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			txID, err := stun.ParseBindingRequest(buffer[:n])
			if err != nil {
				continue
			}
			f.mu.Lock()
			index := len(f.forged)
			// A low address, so that sorting by address would rank it
			// before the real ones.
			forged := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 1 + byte(index>>8), byte(index)}), source.Port())
			f.forged = append(f.forged, forged)
			f.mu.Unlock()
			conn.WriteToUDPAddrPort(stun.Response(txID, forged), source)
		}
	}()
	return netip.AddrPortFrom(iface.V4(), 3478)
}

func (f *forgingSTUN) isForged(addr netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, forged := range f.forged {
		if forged.Addr() == addr {
			return true
		}
	}
	return false
}

// newDirectOnlyPoolLab builds two STUN servers and two sites: a host behind
// a single-address port-preserving NAT, and a remote behind a two-address
// pool NAT whose main-socket choices are bits of seed: bit i for STUN
// destination i, the next bit for every other destination (the host). With
// a liar, a third, lying STUN server is listed too.
func newDirectOnlyPoolLab(t *testing.T, seed int, liar ...*forgingSTUN) (*directOnlyNATLab, *directOnlyPoolNAT) {
	t.Helper()
	inet := natlab.NewInternet()
	lab := &directOnlyNATLab{t: t, start: time.Now()}
	lab.logf = func(format string, args ...any) {
		t.Helper()
		t.Logf("%8s: %s", time.Since(lab.start).Truncate(time.Millisecond), fmt.Sprintf(format, args...))
	}
	for index := range 2 {
		machine := &natlab.Machine{Name: fmt.Sprintf("stun-%d", index)}
		iface := machine.Attach("eth0", inet)
		udp, cleanup := stuntest.ServeWithPacketListener(t, machine)
		t.Cleanup(cleanup)
		lab.stunAddrs = append(lab.stunAddrs, netip.AddrPortFrom(iface.V4(), uint16(udp.Port)))
	}
	for _, forging := range liar {
		machine := &natlab.Machine{Name: "stun-liar"}
		iface := machine.Attach("eth0", inet)
		lab.stunAddrs = append(lab.stunAddrs, forging.serve(t, machine, iface))
	}
	site := func(name, prefix string, nat *directOnlyPoolNAT, poolSize int) *natlab.Machine {
		natMachine := &natlab.Machine{Name: name + "-nat"}
		for index := range poolSize {
			nat.wan = append(nat.wan, natMachine.Attach(fmt.Sprintf("wan%d", index), inet))
		}
		lan := &natlab.Network{Name: name + "-lan", Prefix4: netip.MustParsePrefix(prefix)}
		nat.lan = natMachine.Attach("lan", lan)
		lan.SetDefaultGateway(nat.lan)
		natMachine.PacketHandler = nat
		peer := &natlab.Machine{Name: name, PacketHandler: &natlab.Firewall{SessionTimeout: 2 * time.Minute}}
		peer.Attach("eth0", lan)
		return peer
	}
	lab.host = site("host", "192.168.0.0/24", &directOnlyPoolNAT{}, 1)
	remoteNAT := &directOnlyPoolNAT{mainPort: directOnlyPoolLabRemotePort}
	remoteNAT.mainChoice = func(dst netip.AddrPort) int {
		bit := slices.Index(lab.stunAddrs, dst)
		if bit < 0 {
			bit = len(lab.stunAddrs)
		}
		return seed >> bit & 1
	}
	lab.remote = site("remote", "192.168.1.0/24", remoteNAT, 2)
	return lab, remoteNAT
}

func stunCandidates(endpoints []tailcfg.Endpoint) []netip.AddrPort {
	var candidates []netip.AddrPort
	for _, endpoint := range endpoints {
		if endpoint.Type == tailcfg.EndpointSTUN {
			candidates = append(candidates, endpoint.Addr)
		}
	}
	slices.SortFunc(candidates, netip.AddrPort.Compare)
	return candidates
}

type poolRendezvousResult struct {
	stunAddrs        []netip.AddrPort
	pool             []netip.Addr // the remote NAT's public addresses
	remoteCandidates []netip.AddrPort
	transit          time.Duration
	learningOpened   int
	learningClosed   int
	destinations     map[netip.AddrPort]int
}

// runPoolRendezvous starts both peers, exchanges their published candidates
// once, and measures the first remote-to-host packet within limit.
func runPoolRendezvous(t *testing.T, seed int, refuseLearningSockets bool, limit time.Duration, afterTransit func(*directOnlyNATLab, *labPeer, *recordingListener)) poolRendezvousResult {
	lab, remoteNAT := newDirectOnlyPoolLab(t, seed)
	hostIdentity := newDirectOnlyLabIdentity(1)
	remoteIdentity := newDirectOnlyLabIdentity(2)
	listener := &recordingListener{
		inner:       lab.remote,
		armed:       true,
		mainPort:    directOnlyPoolLabRemotePort,
		refuseExtra: refuseLearningSockets,
	}
	host := lab.newPeer("host", lab.host, hostIdentity, 0)
	remote := lab.newPeer("remote", listener, remoteIdentity, directOnlyPoolLabRemotePort)
	defer host.Close()
	defer remote.Close()
	if port := remote.conn.LocalPort(); port != directOnlyPoolLabRemotePort {
		t.Fatalf("remote bound port %d, want %d", port, directOnlyPoolLabRemotePort)
	}
	hostEndpoints := host.waitEndpoints(t)
	remoteEndpoints := remote.waitEndpoints(t)
	result := poolRendezvousResult{stunAddrs: lab.stunAddrs, remoteCandidates: stunCandidates(remoteEndpoints)}
	for _, wan := range remoteNAT.wan {
		result.pool = append(result.pool, wan.V4())
	}

	// The main socket's own STUN view, as 0.1.16 advertised it.
	var mainView []netip.Addr
	for _, stunAddr := range lab.stunAddrs {
		if addr := remoteNAT.mainSocketChoice(stunAddr); !slices.Contains(mainView, addr) {
			mainView = append(mainView, addr)
		}
	}
	lab.logf("seed %03b: main socket STUN view %v, toward host %v, advertised %v",
		seed, mainView, remoteNAT.mainSocketChoice(stunCandidates(hostEndpoints)[0]), result.remoteCandidates)

	host.mustInstall(t, remote, 2, remoteEndpoints)
	remote.mustInstall(t, host, 1, hostEndpoints)
	result.transit = firstTransit(remote, host, time.Now(), limit)
	result.learningOpened, result.learningClosed, result.destinations = listener.snapshot()
	for _, peer := range []*labPeer{host, remote} {
		if counters := peer.conn.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
			t.Errorf("forbidden transport attempted: %+v", counters)
		}
	}
	if afterTransit != nil && result.transit >= 0 {
		afterTransit(lab, remote, listener)
	}
	return result
}

// TestDirectOnlyNATPoolRendezvous is the regression gate for NATs that pick
// the public IPv4 address per destination. It enumerates every main-socket
// assignment of the two pool addresses to the two STUN servers and the host.
// In the unlucky ones both STUN servers see one address while traffic to the
// host leaves through the other; 0.1.16 advertised only the first and never
// connected. Every assignment must advertise both addresses with the
// preserved port and form the direct path.
func TestDirectOnlyNATPoolRendezvous(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second natlab rendezvous measurement")
	}
	for seed := range 8 {
		t.Run(fmt.Sprintf("seed-%03b", seed), func(t *testing.T) {
			t.Parallel()
			result := runPoolRendezvous(t, seed, false, 15*time.Second, nil)
			var want []netip.AddrPort
			for _, addr := range result.pool {
				want = append(want, netip.AddrPortFrom(addr, directOnlyPoolLabRemotePort))
			}
			if !slices.Equal(result.remoteCandidates, want) {
				t.Errorf("remote advertised STUN candidates %v, want both pool addresses %v", result.remoteCandidates, want)
			}
			if result.transit < 0 {
				t.Fatal("remote never reached the host directly")
			}
			// One learning round at startup: three sockets, all closed,
			// sending only to the compiled STUN destinations.
			if result.learningOpened != directOnlyPoolProbeSockets || result.learningClosed != result.learningOpened {
				t.Errorf("learning sockets opened=%d closed=%d, want %d opened and all closed",
					result.learningOpened, result.learningClosed, directOnlyPoolProbeSockets)
			}
			for destination := range result.destinations {
				if !slices.Contains(result.stunAddrs, destination) {
					t.Errorf("learning socket sent to %v, outside the STUN list %v", destination, result.stunAddrs)
				}
			}
			for _, destination := range result.stunAddrs {
				if result.destinations[destination] < directOnlyPoolProbeSockets {
					t.Errorf("learning sockets sent %d requests to %v, want one per socket", result.destinations[destination], destination)
				}
			}
		})
	}
}

// TestDirectOnlyNATPoolWithoutLearningFails reproduces 0.1.16 on the unlucky
// assignment: without learning sockets, the remote advertises only the
// address both STUN servers saw, and the host's filter drops everything that
// arrives from the other one.
func TestDirectOnlyNATPoolWithoutLearningFails(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second natlab rendezvous measurement")
	}
	const unlucky = 0b100 // both STUN servers see the first address; the host sees the second
	result := runPoolRendezvous(t, unlucky, true, 8*time.Second, nil)
	if want := []netip.AddrPort{netip.AddrPortFrom(result.pool[0], directOnlyPoolLabRemotePort)}; !slices.Equal(result.remoteCandidates, want) {
		t.Fatalf("remote advertised %v without learning sockets, want only %v", result.remoteCandidates, want)
	}
	if result.transit >= 0 {
		t.Fatalf("direct path formed in %v without the pool; the lab no longer reproduces the failure", result.transit)
	}
	if result.learningOpened != 0 {
		t.Fatalf("refused learning sockets were opened %d times", result.learningOpened)
	}
}

// TestDirectOnlyNATPoolRelearnsAfterLinkChange checks that a rebind clears
// the remembered pool and the next refresh learns it again with a new round
// of short-lived sockets.
func TestDirectOnlyNATPoolRelearnsAfterLinkChange(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second natlab rendezvous measurement")
	}
	runPoolRendezvous(t, 0b100, false, 15*time.Second, func(lab *directOnlyNATLab, remote *labPeer, listener *recordingListener) {
		if addrs, _ := remote.conn.directOnlyNATPool.snapshot(time.Now()); len(addrs) != 2 {
			t.Fatalf("pool before rebind = %v, want two addresses", addrs)
		}
		remote.conn.Rebind()
		if addrs, _ := remote.conn.directOnlyNATPool.snapshot(time.Now()); len(addrs) != 0 {
			t.Fatalf("pool after rebind = %v, want empty", addrs)
		}
		remote.conn.ReSTUN("test-link-change")
		deadline := time.Now().Add(10 * time.Second)
		for {
			opened, closed, _ := listener.snapshot()
			addrs, _ := remote.conn.directOnlyNATPool.snapshot(time.Now())
			if opened == 2*directOnlyPoolProbeSockets && closed == opened && len(addrs) == 2 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("after link change: learning sockets opened=%d closed=%d, pool %v", opened, closed, addrs)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func TestDirectOnlyPoolProbeSendsOnlyToSTUNList(t *testing.T) {
	options := directOnlyTestOptions(t)
	c, err := NewConn(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	request := stun.Request(stun.NewTxID())
	for _, destination := range []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:3479"),
		netip.MustParseAddrPort("192.0.2.1:3478"),
		netip.MustParseAddrPort("[::1]:3478"),
	} {
		if err := c.sendDirectOnlyPoolProbe(pc, request, destination); !errors.Is(err, ErrDirectOnlyEgress) {
			t.Fatalf("probe to %v = %v, want ErrDirectOnlyEgress", destination, err)
		}
	}
	if got := c.DirectOnlyCounters().EgressAttempts; got != 3 {
		t.Fatalf("prohibited egress attempts = %d, want 3", got)
	}
	if err := c.sendDirectOnlyPoolProbe(pc, request, options.DirectSTUNEndpoints[0]); err != nil {
		t.Fatalf("probe to the listed STUN destination: %v", err)
	}
	if got := c.DirectOnlyCounters().EgressAttempts; got != 3 {
		t.Fatalf("allowed probe counted as prohibited: %d", got)
	}
}

func TestDirectOnlyRebindClearsNATPool(t *testing.T) {
	c, err := NewConn(directOnlyTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	generation, _, _ := c.directOnlyNATPool.beginRefresh(time.Now(), c.directOnlyLinkFingerprint())
	c.directOnlyNATPool.observe(time.Now(), generation, poolObs(1, "45.0.0.1:41641", 2, "45.0.0.1:41641"))
	c.directOnlyNATPool.markLearned(generation)
	if addrs, _ := c.directOnlyNATPool.snapshot(time.Now()); len(addrs) != 1 {
		t.Fatalf("pool = %v", addrs)
	}
	c.Rebind()
	if addrs, _ := c.directOnlyNATPool.snapshot(time.Now()); len(addrs) != 0 {
		t.Fatalf("pool after rebind = %v, want empty", addrs)
	}
	if _, learn, _ := c.directOnlyNATPool.beginRefresh(time.Now(), c.directOnlyLinkFingerprint()); !learn {
		t.Fatal("rebind did not schedule a learning round")
	}
}

// resetOnFirstReadListener opens sockets whose first read fails the way a
// Windows UDP socket reports an earlier ICMP port unreachable
// (WSAECONNRESET) when it lacks ICMP error immunity.
type resetOnFirstReadListener struct {
	inner nettype.PacketListener
}

func (l resetOnFirstReadListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := l.inner.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &resetOnFirstReadConn{PacketConn: pc}, nil
}

type resetOnFirstReadConn struct {
	net.PacketConn
	reads atomic.Int32
}

func (c *resetOnFirstReadConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	if c.reads.Add(1) == 1 {
		return 0, netip.AddrPort{}, &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNRESET}
	}
	return c.PacketConn.(nettype.PacketConn).ReadFromUDPAddrPort(b)
}

func (c *resetOnFirstReadConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.PacketConn.(nettype.PacketConn).WriteToUDPAddrPort(b, addr)
}

func TestDirectOnlyPoolProbeSurvivesTransientReadErrors(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	t.Cleanup(cleanup)
	destination := netip.MustParseAddrPort(stunAddr.String())
	options := directOnlyTestOptions(t)
	options.DirectSTUNEndpoints = []netip.AddrPort{destination}
	options.TestOnlyPacketListener = resetOnFirstReadListener{inner: localhostListener{}}
	c, err := NewConn(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), directOnlyPoolProbeTimeout)
	defer cancel()
	observations := c.probeDirectOnlyPoolSocket(ctx, []netip.AddrPort{destination})
	if len(observations) != 1 || observations[0].destination != destination || !observations[0].mapped.IsValid() {
		t.Fatalf("observations after a transient read error = %+v, want one answer from %v", observations, destination)
	}
}

// TestDirectOnlyNATPoolResistsForgedSTUN lists a lying STUN server that
// answers every request with a new forged address on the real mapped port.
// No forged address may enter the pool, the real pool addresses must still
// be advertised ahead of all but the current first responder's answer, and
// the direct path must form.
func TestDirectOnlyNATPoolResistsForgedSTUN(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second natlab rendezvous measurement")
	}
	liar := new(forgingSTUN)
	// Both honest servers see the first pool address; the host sees the
	// second (bit 3: destinations 0-2 are the STUN servers).
	lab, remoteNAT := newDirectOnlyPoolLab(t, 0b1000, liar)
	listener := &recordingListener{inner: lab.remote, armed: true, mainPort: directOnlyPoolLabRemotePort}
	host := lab.newPeer("host", lab.host, newDirectOnlyLabIdentity(1), 0)
	remote := lab.newPeer("remote", listener, newDirectOnlyLabIdentity(2), directOnlyPoolLabRemotePort)
	defer host.Close()
	defer remote.Close()
	hostEndpoints := host.waitEndpoints(t)
	remote.waitEndpoints(t)
	var real []netip.AddrPort
	for _, wan := range remoteNAT.wan {
		real = append(real, netip.AddrPortFrom(wan.V4(), directOnlyPoolLabRemotePort))
	}
	// Several refreshes, each forging a new address.
	for range 4 {
		remote.conn.ReSTUN("test-forged-refresh")
		time.Sleep(200 * time.Millisecond)
	}
	addrs, _ := remote.conn.directOnlyNATPool.snapshot(time.Now())
	for _, addr := range addrs {
		if liar.isForged(addr) {
			t.Errorf("forged address %v entered the pool %v", addr, addrs)
		}
	}
	endpoints := remote.latestEndpoints()
	liar.mu.Lock()
	lab.logf("forged answers so far: %d", len(liar.forged))
	liar.mu.Unlock()
	var order []netip.AddrPort
	for _, endpoint := range endpoints {
		if endpoint.Type == tailcfg.EndpointSTUN {
			order = append(order, endpoint.Addr)
		}
	}
	lastReal, forgedBefore := -1, 0
	for index, addr := range order {
		if slices.Contains(real, addr) {
			lastReal = index
		}
	}
	for _, addr := range order[:max(lastReal, 0)] {
		if liar.isForged(addr.Addr()) {
			forgedBefore++
		}
	}
	for _, want := range real {
		if !slices.Contains(order, want) {
			t.Errorf("real pool candidate %v not advertised: %v", want, order)
		}
	}
	// Only the current report's first responder (possibly the liar) may
	// precede a real address; cached forged answers follow them.
	lab.logf("advertised STUN candidates in order: %v", order)
	if forgedBefore > 1 {
		t.Errorf("%d forged candidates precede a real one: %v", forgedBefore, order)
	}
	host.mustInstall(t, remote, 2, endpoints)
	remote.mustInstall(t, host, 1, hostEndpoints)
	if transit := firstTransit(remote, host, time.Now(), 15*time.Second); transit < 0 {
		t.Fatal("remote never reached the host directly")
	}
	if counters := remote.conn.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Errorf("forbidden transport attempted: %+v", counters)
	}
}
