// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build waifus_direct_only

package magicsock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
	"tailscale.com/wgengine/wglog"
)

// directOnlyNATLab is a two-site natlab topology in which each peer sits
// behind an endpoint-independent-mapping NAT with an address-and-port
// dependent filter, the common home-router shape. Neither side can receive
// an unsolicited packet from the other until it has sent one to that exact
// public endpoint itself, and there is no DERP to carry a CallMeMaybe.
type directOnlyNATLab struct {
	t        *testing.T
	stunAddr netip.AddrPort
	host     *natlab.Machine
	remote   *natlab.Machine
	start    time.Time
	logf     logger.Logf
}

func newDirectOnlyNATLab(t *testing.T) *directOnlyNATLab {
	t.Helper()
	inet := natlab.NewInternet()
	stunMachine := &natlab.Machine{Name: "stun"}
	stunInterface := stunMachine.Attach("eth0", inet)

	site := func(name string, prefix string) *natlab.Machine {
		natMachine := &natlab.Machine{Name: name + "-nat"}
		lan := &natlab.Network{Name: name + "-lan", Prefix4: netip.MustParsePrefix(prefix)}
		wan := natMachine.Attach("wan", inet)
		lanInterface := natMachine.Attach("lan", lan)
		lan.SetDefaultGateway(lanInterface)
		natMachine.PacketHandler = &natlab.SNAT44{
			Machine:           natMachine,
			ExternalInterface: wan,
			MappingTimeout:    2 * time.Minute,
			Firewall: &natlab.Firewall{
				TrustedInterface: lanInterface,
				SessionTimeout:   2 * time.Minute,
			},
		}
		peer := &natlab.Machine{Name: name, PacketHandler: &natlab.Firewall{SessionTimeout: 2 * time.Minute}}
		peer.Attach("eth0", lan)
		return peer
	}
	lab := &directOnlyNATLab{
		t:      t,
		host:   site("host", "192.168.0.0/24"),
		remote: site("remote", "192.168.1.0/24"),
		start:  time.Now(),
	}
	stunUDP, stunCleanup := stuntest.ServeWithPacketListener(t, stunMachine)
	t.Cleanup(stunCleanup)
	lab.stunAddr = netip.AddrPortFrom(stunInterface.V4(), uint16(stunUDP.Port))
	lab.logf = func(format string, args ...any) {
		t.Helper()
		t.Logf("%8s: %s", time.Since(lab.start).Truncate(time.Millisecond), fmt.Sprintf(format, args...))
	}
	return lab
}

type directOnlyLabIdentity struct {
	node  key.NodePrivate
	disco key.DiscoPrivate
	addr  netip.Prefix
}

func newDirectOnlyLabIdentity(index byte) directOnlyLabIdentity {
	return directOnlyLabIdentity{
		node:  key.NewNode(),
		disco: key.NewDisco(),
		addr:  netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, index}), 32),
	}
}

// labPeer is one direct-only magicsock plus WireGuard device. Endpoint
// updates are retained so the test coordinator can choose when to deliver
// them, standing in for authenticated encrypted endpoint coordination.
type labPeer struct {
	*magicStack
	identity directOnlyLabIdentity

	mu        sync.Mutex
	endpoints []tailcfg.Endpoint
	changed   chan struct{}
}

func (lab *directOnlyNATLab) newPeer(
	name string,
	machine nettype.PacketListener,
	identity directOnlyLabIdentity,
	port uint16,
) *labPeer {
	t := lab.t
	t.Helper()
	logf := logger.WithPrefix(logger.Discard, name+": ")
	if testing.Verbose() && false {
		logf = logger.WithPrefix(lab.logf, name+": ")
	}
	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	peer := &labPeer{identity: identity, changed: make(chan struct{}, 1)}
	var registry usermetric.Registry
	var wireguard atomic.Pointer[device.Device]
	conn, err := NewConn(Options{
		// Mirror wgengine: report WireGuard state and start a handshake
		// when a direct path validates.
		PeerByKeyFunc: func(peerKey key.NodePublic) (wgint.Peer, bool) {
			if dev := wireguard.Load(); dev != nil {
				if wgPeer, ok := dev.LookupActivePeer(peerKey.Raw32()); ok {
					return wgint.PeerOf(wgPeer), true
				}
			}
			return wgint.Peer{}, false
		},
		DirectPathUpFunc: func(peerKey key.NodePublic) {
			if dev := wireguard.Load(); dev != nil {
				if wgPeer := dev.LookupPeer(peerKey.Raw32()); wgPeer != nil {
					_ = wgPeer.SendHandshakeInitiation(false)
				}
			}
		},
		DirectOnly:             true,
		DirectSTUNEndpoints:    []netip.AddrPort{lab.stunAddr},
		ForceNodeKey:           identity.node,
		ForceDiscoKey:          identity.disco,
		Port:                   port,
		NetMon:                 netMon,
		EventBus:               bus,
		Metrics:                &registry,
		Logf:                   logf,
		HealthTracker:          health.NewTracker(bus),
		DisablePortMapper:      true,
		TestOnlyPacketListener: machine,
		EndpointsFunc: func(endpoints []tailcfg.Endpoint) {
			peer.mu.Lock()
			peer.endpoints = append([]tailcfg.Endpoint(nil), endpoints...)
			peer.mu.Unlock()
			select {
			case peer.changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("constructing direct-only magicsock: %v", err)
	}
	if err := conn.SetPrivateKey(identity.node); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	channelTUN := tuntest.NewChannelTUN()
	wrapped := tstun.Wrap(logf, channelTUN.TUN(), &registry, bus)
	wrapped.SetFilter(filter.NewAllowAllForTest(logf))
	wrapped.Start()
	wgLogger := wglog.NewLogger(logf, nil)
	wgDevice := wgcfg.NewDevice(wrapped, conn.Bind(), wgLogger.DeviceLogger)
	wireguard.Store(wgDevice)
	wgDevice.Up()
	peer.magicStack = &magicStack{
		privateKey: identity.node,
		conn:       conn,
		tun:        channelTUN,
		tsTun:      wrapped,
		dev:        wgDevice,
		wgLogger:   wgLogger,
		netMon:     netMon,
		metrics:    &registry,
	}
	return peer
}

func (peer *labPeer) waitEndpoints(t *testing.T) []tailcfg.Endpoint {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		peer.mu.Lock()
		endpoints := append([]tailcfg.Endpoint(nil), peer.endpoints...)
		peer.mu.Unlock()
		for _, endpoint := range endpoints {
			if endpoint.Type == tailcfg.EndpointSTUN {
				return endpoints
			}
		}
		select {
		case <-peer.changed:
		case <-deadline:
			t.Fatalf("no STUN-derived endpoint was discovered")
		}
	}
}

func (peer *labPeer) latestEndpoints() []tailcfg.Endpoint {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return append([]tailcfg.Endpoint(nil), peer.endpoints...)
}

// install hands self one full map naming peer at the given candidates, as
// the helper's pair adapter does after an authenticated endpoint update.
func (self *labPeer) install(peer *labPeer, peerID tailcfg.NodeID, candidates []tailcfg.Endpoint) error {
	selfNode := (&tailcfg.Node{
		ID:        peerID ^ 3,
		Key:       self.identity.node.Public(),
		DiscoKey:  self.identity.disco.Public(),
		Addresses: []netip.Prefix{self.identity.addr},
	}).View()
	peerNode := (&tailcfg.Node{
		ID:         peerID,
		Key:        peer.identity.node.Public(),
		DiscoKey:   peer.identity.disco.Public(),
		Addresses:  []netip.Prefix{peer.identity.addr},
		AllowedIPs: []netip.Prefix{peer.identity.addr},
		Endpoints:  epFromTyped(candidates),
	}).View()
	if err := self.conn.SetNetworkMap(selfNode, []tailcfg.NodeView{peerNode}); err != nil {
		return fmt.Errorf("SetNetworkMap: %w", err)
	}
	config := &wgcfg.Config{PrivateKey: self.identity.node, Addresses: []netip.Prefix{self.identity.addr}}
	if err := self.Reconfig(config, []tailcfg.NodeView{peerNode}); err != nil {
		return fmt.Errorf("Reconfig: %w", err)
	}
	return nil
}

func (self *labPeer) mustInstall(t *testing.T, peer *labPeer, peerID tailcfg.NodeID, candidates []tailcfg.Endpoint) {
	t.Helper()
	if err := self.install(peer, peerID, candidates); err != nil {
		t.Fatal(err)
	}
}

// installLater delivers candidates after delay, standing in for the
// authenticated coordination round trip.
func (self *labPeer) installLater(t *testing.T, delay time.Duration, peer *labPeer, peerID tailcfg.NodeID) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(delay)
		if err := self.install(peer, peerID, peer.latestEndpoints()); err != nil {
			t.Error(err)
		}
	}()
	return done
}

// drainInbound discards deliveries queued behind the unbuffered test TUN by
// an earlier phase, until the device has been quiet for a moment.
func drainInbound(peer *labPeer) {
	quiet := time.NewTimer(300 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case <-peer.tun.Inbound:
			quiet.Reset(300 * time.Millisecond)
		case <-quiet.C:
			return
		}
	}
}

// firstTransit models an application dial that starts at started: it emits a
// packet from src every 250ms and returns when the first one reaches dst,
// measured from started, or -1 after limit.
func firstTransit(src, dst *labPeer, started time.Time, limit time.Duration) time.Duration {
	deadline := time.After(limit)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	send := func() {
		packet := tuntest.Ping(dst.identity.addr.Addr(), src.identity.addr.Addr())
		select {
		case src.tun.Outbound <- packet:
		case <-deadline:
		}
	}
	send()
	for {
		select {
		case <-dst.tun.Inbound:
			return time.Since(started)
		case <-ticker.C:
			send()
		case <-deadline:
			return -1
		}
	}
}

func waitForTransit(t *testing.T, src, dst *labPeer) {
	t.Helper()
	drainInbound(dst)
	if elapsed := firstTransit(src, dst, time.Now(), 90*time.Second); elapsed < 0 {
		t.Fatalf("no direct transit from %v to %v", src, dst)
	}
}

type rendezvousCase struct {
	name string
	// restart selects which side is replaced by a new process with the same
	// pair identity: "remote", "host", or "" for a first contact where both
	// sides start without each other's current candidates.
	restart string
	// stablePort reuses the replaced instance's UDP port, as a helper with a
	// fixed per-pair port preference does.
	stablePort bool
	// coordinationDelay is how long after the (re)start the fresh endpoints
	// reach the peer through authenticated coordination.
	coordinationDelay time.Duration
	// limit is the regression bound on the measured latency.
	limit time.Duration
}

// runRendezvous measures the user-visible time from a (re)started direct-only
// process to the first remote-to-host application packet, with the remote
// dialing from the moment the (re)started side is up. The surviving side
// keeps the previous candidates until coordination delivers new ones; the
// restarted side starts from its durable copy of the peer's candidates.
func runRendezvous(t *testing.T, test rendezvousCase) time.Duration {
	lab := newDirectOnlyNATLab(t)
	hostIdentity := newDirectOnlyLabIdentity(1)
	remoteIdentity := newDirectOnlyLabIdentity(2)

	var host, remote *labPeer
	var started time.Time
	var delivered <-chan struct{}
	if test.restart == "" {
		host = lab.newPeer("host", lab.host, hostIdentity, 0)
		remote = lab.newPeer("remote", lab.remote, remoteIdentity, 0)
		defer host.Close()
		defer remote.Close()
		host.waitEndpoints(t)
		remote.waitEndpoints(t)
		host.mustInstall(t, remote, 2, nil)
		remote.mustInstall(t, host, 1, nil)
		started = time.Now()
		toRemote := remote.installLater(t, test.coordinationDelay, host, 1)
		toHost := host.installLater(t, test.coordinationDelay, remote, 2)
		both := make(chan struct{})
		go func() { <-toRemote; <-toHost; close(both) }()
		delivered = both
	} else {
		host = lab.newPeer("host", lab.host, hostIdentity, 0)
		remote = lab.newPeer("remote", lab.remote, remoteIdentity, 0)
		host.mustInstall(t, remote, 2, remote.waitEndpoints(t))
		remote.mustInstall(t, host, 1, host.waitEndpoints(t))
		waitForTransit(t, remote, host)
		waitForTransit(t, host, remote)
		previous, machine, identity := remote, lab.remote, remoteIdentity
		survivor, replacementID := host, tailcfg.NodeID(2)
		if test.restart == "host" {
			previous, machine, identity = host, lab.host, hostIdentity
			survivor, replacementID = remote, 1
		}
		port := previous.conn.LocalPort()
		previous.Close()
		// Let the survivor idle briefly with the old candidates, as during a
		// helper restart.
		time.Sleep(time.Second)
		if !test.stablePort {
			port = 0
		}
		drainInbound(host)
		replacement := lab.newPeer(test.restart, machine, identity, port)
		defer replacement.Close()
		defer survivor.Close()
		started = time.Now()
		replacement.mustInstall(t, survivor, replacementID^3, survivor.latestEndpoints())
		if test.restart == "host" {
			host = replacement
		} else {
			remote = replacement
		}
		delivered = survivor.installLater(t, test.coordinationDelay, replacement, replacementID)
	}
	elapsed := firstTransit(remote, host, started, 90*time.Second)
	<-delivered
	lab.logf("%s: first remote-to-host transit %v after start", test.name, elapsed.Truncate(time.Millisecond))
	if elapsed < 0 {
		t.Fatalf("%s: remote never reached the host", test.name)
	}
	if test.limit > 0 && elapsed > test.limit {
		t.Errorf("%s: first transit took %v, want at most %v", test.name, elapsed, test.limit)
	}
	return elapsed
}

// TestDirectOnlyRendezvousLatency is the regression gate for direct-only path
// formation without DERP. Before inbound-ping answers, held handshakes, and
// the path-up handshake, the same topology needed about five seconds beyond
// coordination for every case (the disco ping interval plus wireguard-go's
// handshake retransmission), and a host restart with a surviving remote took
// 16 to 21 seconds (wireguard-go's keepalive timeout on stale session keys).
func TestDirectOnlyRendezvousLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second natlab rendezvous measurement")
	}
	const slack = 1500 * time.Millisecond
	cases := []rendezvousCase{
		{name: "first-contact/coord-1s", coordinationDelay: time.Second},
		{name: "first-contact/coord-3s", coordinationDelay: 3 * time.Second},
		{name: "remote-restart/random-port/coord-1s", restart: "remote", coordinationDelay: time.Second},
		{name: "remote-restart/random-port/coord-3s", restart: "remote", coordinationDelay: 3 * time.Second},
		{name: "remote-restart/stable-port/coord-3s", restart: "remote", stablePort: true, coordinationDelay: 3 * time.Second},
		{name: "host-restart/random-port/coord-3s", restart: "host", coordinationDelay: 3 * time.Second},
		{name: "host-restart/stable-port/coord-3s", restart: "host", stablePort: true, coordinationDelay: 3 * time.Second},
	}
	for _, test := range cases {
		test.limit = test.coordinationDelay + slack
		if test.stablePort {
			// The surviving peer's candidates stay valid; coordination is
			// not on the critical path.
			test.limit = slack
		}
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runRendezvous(t, test)
		})
	}
}

// directOnlySinkPeer installs one authorized peer whose only candidate is a
// local UDP sink, so tests can observe exactly what magicsock sends to it.
func directOnlySinkPeer(t *testing.T, options Options) (*Conn, *endpoint, *net.UDPConn, netip.AddrPort) {
	t.Helper()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	c, err := NewConn(options)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPrivateKey(c.directOnlyNodeKey); err != nil {
		t.Fatal(err)
	}
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
	peerNode := directOnlyTestNode(2, 0, false, "100.64.0.2/32").AsStruct()
	address := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	peerNode.Endpoints = []netip.AddrPort{address}
	peer := peerNode.View()
	if err := c.SetNetworkMap(self, []tailcfg.NodeView{peer}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(peer.Key())
	c.mu.Unlock()
	if !ok {
		t.Fatal("missing authorized peer")
	}
	return c, ep, sink, address
}

// readSinkPacket returns the next packet the sink receives within wait, and
// whether it was a disco message.
func readSinkPacket(sink *net.UDPConn, wait time.Duration) (packet []byte, isDisco, ok bool) {
	buffer := make([]byte, 2048)
	sink.SetReadDeadline(time.Now().Add(wait))
	n, _, err := sink.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return nil, false, false
	}
	return buffer[:n], bytes.HasPrefix(buffer[:n], []byte(disco.Magic)), true
}

// drainSink discards everything the sink receives until it is quiet.
func drainSink(sink *net.UDPConn) {
	for {
		if _, _, ok := readSinkPacket(sink, 100*time.Millisecond); !ok {
			return
		}
	}
}

func wireGuardTestMessage(messageType uint32, size int) []byte {
	message := make([]byte, size)
	binary.LittleEndian.PutUint32(message, messageType)
	for index := 4; index < size; index++ {
		message[index] = byte(index)
	}
	return message
}

func TestDirectOnlyAnswersInboundPingWithoutTrustedPath(t *testing.T) {
	c, ep, sink, address := directOnlySinkPeer(t, directOnlyTestOptions(t))
	// The full map itself starts discovery to the new candidate.
	if _, isDisco, ok := readSinkPacket(sink, time.Second); !ok || !isDisco {
		t.Fatal("full map did not probe the advertised candidate")
	}
	drainSink(sink)

	// The regular five-second interval would suppress another ping now; an
	// inbound ping from the candidate must be answered anyway.
	ep.answerDirectOnlyRendezvous(address)
	if _, isDisco, ok := readSinkPacket(sink, time.Second); !ok || !isDisco {
		t.Fatal("inbound ping without a trusted path was not answered")
	}
	drainSink(sink)
	ep.answerDirectOnlyRendezvous(address)
	if _, _, ok := readSinkPacket(sink, 200*time.Millisecond); ok {
		t.Fatal("rendezvous answers to one address were not rate limited")
	}

	// A trusted direct path needs no rendezvous.
	ep.mu.Lock()
	ep.endpointState[address].lastRendezvousAnswer = mono.Now().Add(-time.Minute)
	ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: address}})
	ep.trustBestAddrUntil = mono.Now().Add(time.Minute)
	ep.mu.Unlock()
	ep.answerDirectOnlyRendezvous(address)
	if _, _, ok := readSinkPacket(sink, 200*time.Millisecond); ok {
		t.Fatal("inbound ping on a trusted path triggered an extra probe")
	}

	// Unknown sources are never probed by this path.
	ep.mu.Lock()
	ep.trustBestAddrUntil = 0
	ep.mu.Unlock()
	ep.answerDirectOnlyRendezvous(netip.MustParseAddrPort("127.0.0.1:9"))
	if _, _, ok := readSinkPacket(sink, 200*time.Millisecond); ok {
		t.Fatal("answer was sent somewhere other than the pinging candidate")
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("forbidden transport attempted: %+v", counters)
	}
}

func TestDirectOnlyHoldsOnlyHandshakeUntilPathValidates(t *testing.T) {
	const offset = 16
	c, ep, sink, address := directOnlySinkPeer(t, directOnlyTestOptions(t))
	drainSink(sink)
	withOffset := func(message []byte) [][]byte {
		return [][]byte{append(make([]byte, offset), message...)}
	}
	initiation := wireGuardTestMessage(device.MessageInitiationType, device.MessageInitiationSize)
	response := wireGuardTestMessage(device.MessageResponseType, device.MessageResponseSize)
	data := wireGuardTestMessage(device.MessageTransportType, device.MessageTransportSize+64)
	malformed := wireGuardTestMessage(device.MessageInitiationType, device.MessageInitiationSize-1)

	for _, message := range [][]byte{data, malformed} {
		if err := ep.send(withOffset(message), offset); !errors.Is(err, ErrNoDirectPath) {
			t.Fatalf("send without a path = %v, want ErrNoDirectPath", err)
		}
	}
	ep.mu.Lock()
	if ep.heldHandshake != nil {
		ep.mu.Unlock()
		t.Fatal("transport data or a malformed message was held")
	}
	ep.mu.Unlock()
	if err := ep.send(withOffset(initiation), offset); !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("send without a path = %v, want ErrNoDirectPath", err)
	}
	if err := ep.send(withOffset(response), offset); !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("send without a path = %v, want ErrNoDirectPath", err)
	}
	drainSink(sink)

	validate := func(heldAge time.Duration) {
		ep.mu.Lock()
		defer ep.mu.Unlock()
		now := mono.Now()
		ep.heldHandshakeAt = now.Add(-heldAge)
		previous := ep.bestAddr.epAddr
		ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: address}})
		ep.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
		ep.directOnlyPathValidatedLocked(now, previous, false)
	}
	validate(time.Second)
	var sent []byte
	for {
		packet, isDisco, ok := readSinkPacket(sink, time.Second)
		if !ok {
			t.Fatal("held handshake was not sent once the path validated")
		}
		if !isDisco {
			sent = packet
			break
		}
	}
	if !bytes.Equal(sent, response) {
		t.Fatalf("sent %x, want the most recent held handshake message", sent)
	}
	ep.mu.Lock()
	held := ep.heldHandshake
	ep.mu.Unlock()
	if held != nil {
		t.Fatal("held handshake was not cleared after sending")
	}

	// A message older than wireguard-go's own retransmission is dropped.
	ep.mu.Lock()
	ep.clearBestAddrLocked()
	ep.mu.Unlock()
	if err := ep.send(withOffset(initiation), offset); !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("send without a path = %v, want ErrNoDirectPath", err)
	}
	drainSink(sink)
	validate(directOnlyHandshakeHoldTime + time.Second)
	for {
		packet, isDisco, ok := readSinkPacket(sink, 300*time.Millisecond)
		if !ok {
			break
		}
		if !isDisco {
			t.Fatalf("expired held handshake %x was sent", packet)
		}
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("forbidden transport attempted: %+v", counters)
	}
}

func TestDirectOnlyPathUpStartsOneHandshake(t *testing.T) {
	validate := func(ep *endpoint, address netip.AddrPort) {
		ep.mu.Lock()
		defer ep.mu.Unlock()
		now := mono.Now()
		previous := ep.bestAddr.epAddr
		ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: address}})
		ep.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
		ep.directOnlyPathValidatedLocked(now, previous, false)
	}
	newConn := func(t *testing.T) (*endpoint, netip.AddrPort, chan key.NodePublic) {
		calls := make(chan key.NodePublic, 4)
		options := directOnlyTestOptions(t)
		options.DirectPathUpFunc = func(peer key.NodePublic) { calls <- peer }
		_, ep, _, address := directOnlySinkPeer(t, options)
		return ep, address, calls
	}

	t.Run("once", func(t *testing.T) {
		ep, address, calls := newConn(t)
		validate(ep, address)
		select {
		case peer := <-calls:
			if peer != ep.publicKey {
				t.Fatalf("path-up for %v, want %v", peer, ep.publicKey)
			}
		case <-time.After(5 * directOnlyPathUpDelay):
			t.Fatal("first direct path did not start a handshake")
		}
		ep.mu.Lock()
		ep.clearBestAddrLocked()
		ep.mu.Unlock()
		validate(ep, address)
		select {
		case <-calls:
			t.Fatal("later path validation started another handshake")
		case <-time.After(3 * directOnlyPathUpDelay):
		}
	})
	t.Run("lookalike-handshake-does-not-suppress", func(t *testing.T) {
		// Only WireGuard-authenticated handshake state may suppress the
		// hook. A packet that merely has a handshake's type and length,
		// from the peer's own address, must not.
		ep, address, calls := newConn(t)
		forged := wireGuardTestMessage(device.MessageInitiationType, device.MessageInitiationSize)
		if _, _, _, ok := ep.c.receiveIP(forged, address, &epAddrEndpointCache{}); !ok {
			t.Fatal("test packet was not accepted for WireGuard")
		}
		validate(ep, address)
		select {
		case <-calls:
		case <-time.After(5 * directOnlyPathUpDelay):
			t.Fatal("a forged handshake lookalike suppressed the path-up handshake")
		}
	})
	t.Run("held-handshake-sent", func(t *testing.T) {
		ep, address, calls := newConn(t)
		ep.mu.Lock()
		ep.heldHandshake = wireGuardTestMessage(device.MessageInitiationType, device.MessageInitiationSize)
		ep.heldHandshakeAt = mono.Now()
		ep.mu.Unlock()
		validate(ep, address)
		select {
		case <-calls:
			t.Fatal("started a second handshake beside the held one")
		case <-time.After(3 * directOnlyPathUpDelay):
		}
	})
}

func TestDirectPathUpFuncIgnoredOutsideDirectOnly(t *testing.T) {
	options := directOnlyTestOptions(t)
	options.DirectOnly = false
	options.DirectSTUNEndpoints = nil
	options.ForceNodeKey = key.NodePrivate{}
	options.DirectPathUpFunc = func(key.NodePublic) {}
	c, err := NewConn(options)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer c.Close()
	if c.directPathUp != nil {
		t.Fatal("path-up hook installed outside direct-only mode")
	}
}

// TestDirectOnlyRendezvousAnswerThroughAuthenticatedPing drives a sealed disco
// ping from the authorized peer's key through the real receive path, from a
// source the map never advertised, and checks that the answer is a ping to
// exactly that source. The answer goes to the source of an authenticated
// ping, not to a pong-validated path; the pong it elicits is what validates.
func TestDirectOnlyRendezvousAnswerThroughAuthenticatedPing(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	c, err := NewConn(directOnlyTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPrivateKey(c.directOnlyNodeKey); err != nil {
		t.Fatal(err)
	}
	peerDisco := key.NewDisco()
	self := directOnlyTestNode(1, 0, false, "100.64.0.1/32")
	peerNode := directOnlyTestNode(2, 0, false, "100.64.0.2/32").AsStruct()
	peerNode.DiscoKey = peerDisco.Public()
	peerNode.Endpoints = nil
	if err := c.SetNetworkMap(self, []tailcfg.NodeView{peerNode.View()}); err != nil {
		t.Fatal(err)
	}
	shared := peerDisco.Shared(c.DiscoPublicKey())
	seal := func(message disco.Message) []byte {
		packet := append([]byte(disco.Magic), peerDisco.Public().AppendTo(nil)...)
		return append(packet, shared.Seal(message.AppendMarshal(nil))...)
	}
	source := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	readMessages := func(wait time.Duration) []disco.Message {
		var messages []disco.Message
		buffer := make([]byte, 2048)
		for {
			sink.SetReadDeadline(time.Now().Add(wait))
			n, _, err := sink.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return messages
			}
			packet := buffer[:n]
			if !bytes.HasPrefix(packet, []byte(disco.Magic)) || len(packet) < discoHeaderLen {
				t.Fatalf("non-disco packet %x sent to the pinging source", packet)
			}
			clear, ok := shared.Open(packet[discoHeaderLen:])
			if !ok {
				t.Fatal("reply was not sealed to the pinging peer")
			}
			message, err := disco.Parse(clear)
			if err != nil {
				t.Fatal(err)
			}
			messages = append(messages, message)
		}
	}
	countPings := func(messages []disco.Message) (pings, pongs int) {
		for _, message := range messages {
			switch message.(type) {
			case *disco.Ping:
				pings++
			case *disco.Pong:
				pongs++
			}
		}
		return pings, pongs
	}

	// A forged ping (not sealed with the peer's key) gets nothing back.
	forged := append([]byte(disco.Magic), peerDisco.Public().AppendTo(nil)...)
	forged = append(forged, make([]byte, 64)...)
	c.handleDiscoMessage(forged, epAddr{ap: source}, false, key.NodePublic{}, discoRXPathUDP)
	if messages := readMessages(200 * time.Millisecond); len(messages) != 0 {
		t.Fatalf("unauthenticated ping elicited %d messages", len(messages))
	}

	c.handleDiscoMessage(seal(&disco.Ping{TxID: stun.NewTxID()}), epAddr{ap: source}, false, key.NodePublic{}, discoRXPathUDP)
	pings, pongs := countPings(readMessages(500 * time.Millisecond))
	if pongs != 1 || pings == 0 {
		t.Fatalf("authenticated ping from a new source got %d pongs and %d pings, want a pong and a rendezvous ping", pongs, pings)
	}
	// A second ping within the answer interval gets only its pong.
	c.handleDiscoMessage(seal(&disco.Ping{TxID: stun.NewTxID()}), epAddr{ap: source}, false, key.NodePublic{}, discoRXPathUDP)
	if pings, pongs := countPings(readMessages(300 * time.Millisecond)); pongs != 1 || pings != 0 {
		t.Fatalf("repeated ping got %d pongs and %d pings, want only a pong", pongs, pings)
	}
	if counters := c.DirectOnlyCounters(); counters != (DirectOnlyCounters{}) {
		t.Fatalf("forbidden transport attempted: %+v", counters)
	}
}
