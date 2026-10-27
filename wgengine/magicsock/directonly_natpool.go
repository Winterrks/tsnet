// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/sockopts"
	"tailscale.com/net/stun"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/nettype"
)

// Some NATs keep a socket's local port but choose its public IPv4 address per
// destination from a small pool, sticky per socket and destination. A peer may
// then see any pool address, while the fixed STUN list may all have been
// assigned the same one. In direct-only mode there is no DERP CallMeMaybe to
// reveal the address the peer actually sees, so magicsock remembers every pool
// address observed on the current network and, when the NAT evidently keeps
// the port across addresses, advertises each remembered address with the
// current mapped port.
const (
	// directOnlyNATPoolMax bounds the remembered public addresses per
	// network, and so the extra server-reflexive candidates advertised.
	directOnlyNATPoolMax = 8
	// directOnlyNATPoolLifetime is how long an address stays remembered
	// without being observed again.
	directOnlyNATPoolLifetime = 30 * time.Minute
	// directOnlyNATPoolRelearnAge is the age at which a remembered address
	// that the main socket no longer observes triggers another learning
	// round, so that a live pool address is refreshed before it expires.
	directOnlyNATPoolRelearnAge = directOnlyNATPoolLifetime / 2
	// directOnlyPoolProbeSockets is the number of short-lived extra UDP
	// sockets a learning round uses. Each new socket receives fresh
	// per-destination address choices from the NAT.
	directOnlyPoolProbeSockets = 3
	// directOnlyPoolProbeTimeout bounds one learning round.
	directOnlyPoolProbeTimeout = 2 * time.Second
	// directOnlyPoolProbeRetransmit is the delay before an unanswered
	// binding request is sent again, at most twice.
	directOnlyPoolProbeRetransmit = 500 * time.Millisecond
	// directOnlyPoolRoundInterval is the minimum time between learning
	// rounds on one network, so that an unanswered round (no IPv4, blocked
	// UDP) or an address that has really left the pool is not retried on
	// every refresh.
	directOnlyPoolRoundInterval = time.Minute
)

// directOnlyNATPoolTracked bounds every address the pool tracks, admitted or
// not, so that a destination reporting a new address on every refresh cannot
// grow it; unadmitted addresses are evicted first.
const directOnlyNATPoolTracked = 2 * directOnlyNATPoolMax

// directOnlyNATPoolPairs bounds the recorded cross-address port evidence.
const directOnlyNATPoolPairs = 2 * directOnlyNATPoolMax

// directOnlyPoolObservation is one binding response: the fixed STUN
// destination that answered and the mapping it reported.
type directOnlyPoolObservation struct {
	destination netip.AddrPort
	mapped      netip.AddrPort
}

// directOnlyPoolEntry is one tracked public address.
type directOnlyPoolEntry struct {
	lastSeen time.Time
	// reporters are the distinct STUN destinations that reported the
	// address on this network. It is admitted once two have, so that a
	// single lying or spoofed destination cannot add an address.
	reporters map[netip.AddrPort]struct{}
}

func (e *directOnlyPoolEntry) admitted() bool { return len(e.reporters) >= 2 }

// directOnlyNATPool is the per-network memory of observed public IPv4
// addresses. Its zero value is ready to use and needs a learning round.
type directOnlyNATPool struct {
	mu sync.Mutex
	// link identifies the network the pool was learned on; a different
	// link clears the pool.
	link string
	// generation changes whenever the pool is cleared, so observations
	// from a round that straddled a reset are discarded.
	generation uint64
	// entries are the tracked public addresses.
	entries map[netip.Addr]*directOnlyPoolEntry
	// learned reports that a learning round on this link got an answer.
	learned bool
	// lastRound is when the latest learning round on this link started.
	lastRound time.Time
	// lastResetRefresh is when a reset by resetIfUnrelated last asked for
	// an immediate refresh. It survives resets, so that resets cannot
	// trigger refreshes in a loop.
	lastResetRefresh time.Time
	// pairs records, with when it was last seen, each pair of distinct
	// addresses that one socket observed with the same mapped port. A pair
	// of admitted addresses shows that the NAT keeps a socket's port across
	// the addresses it chooses.
	pairs map[[2]netip.Addr]time.Time
}

// directOnlyReservedIPv4 lists IPv4 ranges that are never a NAT's public
// address: this-network, private, shared address space, loopback,
// link-local, IETF protocol assignments, documentation, the 6to4 relay
// anycast, benchmarking, multicast, and reserved (with broadcast).
var directOnlyReservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// directOnlyNATPoolAddress reports whether addr may be remembered as a NAT
// public address: an IPv4 address outside every reserved or special-purpose
// range and outside the Tailscale ranges.
func directOnlyNATPoolAddress(addr netip.Addr) bool {
	if !addr.Is4() || tsaddr.IsTailscaleIP(addr) {
		return false
	}
	for _, prefix := range directOnlyReservedIPv4 {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// resetLocked forgets everything learned and records link as the current
// network.
func (p *directOnlyNATPool) resetLocked(link string) {
	p.link = link
	p.generation++
	p.entries = nil
	p.learned = false
	p.lastRound = time.Time{}
	p.pairs = nil
}

// reset forgets the pool, for example after a rebind or network loss.
func (p *directOnlyNATPool) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetLocked(p.link)
}

// expireLocked drops addresses and evidence not observed within the
// lifetime.
func (p *directOnlyNATPool) expireLocked(now time.Time) {
	for addr, entry := range p.entries {
		if now.Sub(entry.lastSeen) > directOnlyNATPoolLifetime {
			delete(p.entries, addr)
		}
	}
	for pair, at := range p.pairs {
		if now.Sub(at) > directOnlyNATPoolLifetime {
			delete(p.pairs, pair)
		}
	}
}

// beginRefresh switches the pool to link, clearing it if the network
// changed, and returns the generation that this refresh's observations
// belong to and every address tracked before it. It also reports whether
// this refresh should run a learning round: on a new network, until a round
// has been answered, and whenever an admitted address has gone unobserved
// for the relearn age, but at most once per round interval.
func (p *directOnlyNATPool) beginRefresh(now time.Time, link string) (generation uint64, learn bool, remembered []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if link != p.link || p.generation == 0 {
		p.resetLocked(link)
	}
	p.expireLocked(now)
	due := !p.learned
	for addr, entry := range p.entries {
		remembered = append(remembered, addr)
		due = due || entry.admitted() && now.Sub(entry.lastSeen) >= directOnlyNATPoolRelearnAge
	}
	slices.SortFunc(remembered, netip.Addr.Compare)
	if !due || !p.lastRound.IsZero() && now.Sub(p.lastRound) < directOnlyPoolRoundInterval {
		return p.generation, false, remembered
	}
	p.lastRound = now
	return p.generation, true, remembered
}

// resetIfUnrelated clears the pool when the main socket's report, from the
// refresh of generation, shares no address with the addresses remembered
// before that refresh and two different destinations agree on a new
// address (the admission rule): the network changed without a rebind or a
// new link fingerprint (for example the same interface and local address
// behind another NAT). A single destination answering alone, such as a
// lying one, cannot reset it. It returns the generation the report belongs
// to afterwards, whether it reset, and whether the caller should start an
// immediate refresh to learn the new pool, which is allowed at most once
// per round interval.
func (p *directOnlyNATPool) resetIfUnrelated(now time.Time, generation uint64, main []directOnlyPoolObservation, remembered []netip.Addr) (_ uint64, reset, refresh bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation || len(remembered) == 0 {
		return p.generation, false, false
	}
	reporters := make(map[netip.Addr]map[netip.AddrPort]struct{})
	for _, observation := range main {
		addr := observation.mapped.Addr().Unmap()
		if !directOnlyNATPoolAddress(addr) || !observation.destination.IsValid() {
			continue
		}
		if slices.Contains(remembered, addr) {
			return p.generation, false, false
		}
		if reporters[addr] == nil {
			reporters[addr] = make(map[netip.AddrPort]struct{})
		}
		reporters[addr][observation.destination] = struct{}{}
	}
	agreed := false
	for _, destinations := range reporters {
		agreed = agreed || len(destinations) >= 2
	}
	if !agreed {
		return p.generation, false, false
	}
	p.resetLocked(p.link)
	if p.lastResetRefresh.IsZero() || now.Sub(p.lastResetRefresh) >= directOnlyPoolRoundInterval {
		p.lastResetRefresh = now
		refresh = true
	}
	return p.generation, true, refresh
}

// observe records the responses one socket received, and whether they show
// the NAT keeping the socket's port across pool addresses. Observations from
// an earlier generation are ignored.
func (p *directOnlyNATPool) observe(now time.Time, generation uint64, observations []directOnlyPoolObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation {
		return
	}
	addrsByPort := make(map[uint16][]netip.Addr)
	for _, observation := range observations {
		addr := observation.mapped.Addr().Unmap()
		if !directOnlyNATPoolAddress(addr) || !observation.destination.IsValid() {
			continue
		}
		port := observation.mapped.Port()
		if !slices.Contains(addrsByPort[port], addr) {
			addrsByPort[port] = append(addrsByPort[port], addr)
		}
		if p.entries == nil {
			p.entries = make(map[netip.Addr]*directOnlyPoolEntry)
		}
		entry := p.entries[addr]
		if entry == nil {
			entry = &directOnlyPoolEntry{reporters: make(map[netip.AddrPort]struct{})}
			p.entries[addr] = entry
		}
		entry.lastSeen = now
		if len(entry.reporters) < MaxDirectSTUNEndpoints {
			entry.reporters[observation.destination] = struct{}{}
		}
	}
	for _, addrs := range addrsByPort {
		for i := range addrs {
			for j := i + 1; j < len(addrs); j++ {
				pair := [2]netip.Addr{addrs[i], addrs[j]}
				if pair[1].Less(pair[0]) {
					pair[0], pair[1] = pair[1], pair[0]
				}
				if p.pairs == nil {
					p.pairs = make(map[[2]netip.Addr]time.Time)
				}
				p.pairs[pair] = now
			}
		}
	}
	p.expireLocked(now)
	p.boundLocked()
}

// boundLocked evicts the least recently seen addresses beyond the bounds:
// unadmitted ones first, then admitted ones beyond directOnlyNATPoolMax; and
// the least recently seen evidence pairs, those not between two admitted
// addresses first.
func (p *directOnlyNATPool) boundLocked() {
	evict := func(admitted bool) bool {
		var oldest netip.Addr
		var oldestAt time.Time
		for addr, entry := range p.entries {
			if entry.admitted() != admitted {
				continue
			}
			if !oldest.IsValid() || entry.lastSeen.Before(oldestAt) || entry.lastSeen.Equal(oldestAt) && addr.Less(oldest) {
				oldest, oldestAt = addr, entry.lastSeen
			}
		}
		if !oldest.IsValid() {
			return false
		}
		delete(p.entries, oldest)
		return true
	}
	for len(p.entries) > directOnlyNATPoolTracked {
		if !evict(false) {
			evict(true)
		}
	}
	for p.admittedCountLocked() > directOnlyNATPoolMax {
		evict(true)
	}
	for len(p.pairs) > directOnlyNATPoolPairs {
		var oldest [2]netip.Addr
		var oldestAt time.Time
		found, oldestReal := false, true
		for pair, at := range p.pairs {
			real := p.admittedLocked(pair[0]) && p.admittedLocked(pair[1])
			better := !found || oldestReal && !real ||
				oldestReal == real && (at.Before(oldestAt) || at.Equal(oldestAt) && (pair[0].Less(oldest[0]) || pair[0] == oldest[0] && pair[1].Less(oldest[1])))
			if better {
				oldest, oldestAt, oldestReal, found = pair, at, real, true
			}
		}
		delete(p.pairs, oldest)
	}
}

func (p *directOnlyNATPool) admittedLocked(addr netip.Addr) bool {
	entry := p.entries[addr]
	return entry != nil && entry.admitted()
}

func (p *directOnlyNATPool) admittedCountLocked() int {
	count := 0
	for _, entry := range p.entries {
		if entry.admitted() {
			count++
		}
	}
	return count
}

// markLearned records that a learning round of generation got an answer.
func (p *directOnlyNATPool) markLearned(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation == p.generation {
		p.learned = true
	}
}

// snapshot returns the admitted addresses, sorted, and whether one socket on
// this network saw two admitted addresses with the same mapped port.
func (p *directOnlyNATPool) snapshot(now time.Time) (addrs []netip.Addr, crossAddressPort bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	for addr, entry := range p.entries {
		if entry.admitted() {
			addrs = append(addrs, addr)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	for pair := range p.pairs {
		crossAddressPort = crossAddressPort || p.admittedLocked(pair[0]) && p.admittedLocked(pair[1])
	}
	return addrs, crossAddressPort
}

// directOnlyPoolPort returns the mapped port to pair with every admitted
// pool address, given the main socket's report and local port. Every IPv4
// observation of the main socket for an admitted address must share one
// mapped port (observations only one destination vouched for are ignored),
// and either that port is the local port (a port-preserving NAT) or some
// socket on this network saw two admitted addresses with one port (the NAT
// keeps the port across the addresses it chooses). Otherwise the port
// another pool address would carry is unknown and no pool candidate is
// derived.
func directOnlyPoolPort(nr *netcheck.Report, localPort uint16, crossAddressPort bool, admitted []netip.Addr) (uint16, bool) {
	if nr == nil {
		return 0, false
	}
	var port uint16
	for ap := range nr.GlobalV4Counters {
		if !slices.Contains(admitted, ap.Addr().Unmap()) {
			continue
		}
		if port != 0 && ap.Port() != port {
			return 0, false
		}
		port = ap.Port()
	}
	if port != 0 && (port == localPort || crossAddressPort) {
		return port, true
	}
	return 0, false
}

// directOnlyLinkFingerprint identifies the current network by its default
// route interface and that interface's addresses.
func (c *Conn) directOnlyLinkFingerprint() string {
	if c.netMon == nil {
		return ""
	}
	st := c.netMon.InterfaceState()
	if st == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(st.DefaultRouteInterface)
	prefixes := slices.Clone(st.InterfaceIPs[st.DefaultRouteInterface])
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	for _, prefix := range prefixes {
		b.WriteByte(' ')
		b.WriteString(prefix.String())
	}
	return b.String()
}

// directOnlyPoolEndpoints returns a server-reflexive candidate for every
// remembered pool address, carrying the main socket's mapped port, when the
// NAT evidently preserves that port across its addresses. It is empty
// outside direct-only mode.
func (c *Conn) directOnlyPoolEndpoints(nr *netcheck.Report) []netip.AddrPort {
	if !c.directOnly {
		return nil
	}
	addrs, crossAddressPort := c.directOnlyNATPool.snapshot(time.Now())
	port, ok := directOnlyPoolPort(nr, c.LocalPort(), crossAddressPort, addrs)
	if !ok {
		return nil
	}
	endpoints := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		endpoints = append(endpoints, netip.AddrPortFrom(addr, port))
	}
	return endpoints
}

// sendDirectOnlyPoolProbe sends one STUN binding request from a learning
// socket. Like sendUDPNetcheck, it refuses every destination outside the
// immutable direct-only STUN list and counts the attempt as prohibited egress.
func (c *Conn) sendDirectOnlyPoolProbe(pc nettype.PacketConn, b []byte, addr netip.AddrPort) error {
	if !c.directOnly || !addr.Addr().Is4() || !c.directOnlySTUNEndpointAllowed(addr) {
		c.prohibitedEgressAttempts.Add(1)
		return ErrDirectOnlyEgress
	}
	_, err := pc.WriteToUDPAddrPort(b, addr)
	return err
}

// probeDirectOnlyNATPool runs one learning round: a few short-lived extra
// UDP sockets each send a binding request to every IPv4 destination of the
// fixed STUN list, record the public addresses the NAT chose for them, and
// are closed. Their mapped ports belong to those sockets and are never
// advertised. It reports whether any destination answered.
func (c *Conn) probeDirectOnlyNATPool(ctx context.Context, generation uint64) bool {
	if !c.directOnly {
		return false
	}
	var destinations []netip.AddrPort
	for _, endpoint := range c.directSTUNEndpoints {
		if endpoint.Addr().Is4() {
			destinations = append(destinations, endpoint)
		}
	}
	if len(destinations) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, directOnlyPoolProbeTimeout)
	defer cancel()
	var wg sync.WaitGroup
	answered := make([]bool, directOnlyPoolProbeSockets)
	for index := range directOnlyPoolProbeSockets {
		wg.Go(func() {
			observations := c.probeDirectOnlyPoolSocket(ctx, destinations)
			c.directOnlyNATPool.observe(time.Now(), generation, observations)
			answered[index] = len(observations) != 0
		})
	}
	wg.Wait()
	return slices.Contains(answered, true)
}

// directOnlyPoolProbeReadErrors bounds consecutive non-closing read errors
// a learning socket tolerates, such as a Windows WSAECONNRESET left by an
// ICMP port unreachable.
const directOnlyPoolProbeReadErrors = 8

// probeDirectOnlyPoolSocket opens one extra UDP socket, sends a binding
// request to each destination (retransmitting unanswered ones at most twice),
// and returns the responses that match a request's transaction ID and
// destination, in destination order. The socket is closed before it returns.
func (c *Conn) probeDirectOnlyPoolSocket(ctx context.Context, destinations []netip.AddrPort) []directOnlyPoolObservation {
	pc, err := c.listenPacket("udp4", 0)
	if err != nil {
		c.dlogf("[v1] magicsock: direct-only NAT pool probe socket: %v", err)
		return nil
	}
	// As for the main sockets: an ICMP error must not fail later reads.
	if err := sockopts.SetICMPErrImmunity(pc); err != nil {
		c.dlogf("[v1] magicsock: direct-only NAT pool probe socket: %v", err)
	}
	type datagram struct {
		payload []byte
		source  netip.AddrPort
	}
	received := make(chan datagram)
	done := make(chan struct{})
	readerDone := make(chan struct{})
	// Closing the socket ends the reader; not every PacketConn supports
	// read deadlines.
	defer func() {
		close(done)
		pc.Close()
		<-readerDone
	}()
	go func() {
		defer close(readerDone)
		buffer := make([]byte, 1500)
		for failures := 0; ; {
			n, source, err := pc.ReadFromUDPAddrPort(buffer)
			if err != nil {
				failures++
				select {
				case <-done:
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) || failures >= directOnlyPoolProbeReadErrors {
					return
				}
				continue
			}
			failures = 0
			select {
			case received <- datagram{payload: bytes.Clone(buffer[:n]), source: source}:
			case <-done:
				return
			}
		}
	}()

	pending := make(map[stun.TxID]netip.AddrPort, len(destinations))
	answers := make(map[netip.AddrPort]netip.AddrPort, len(destinations))
	send := func() {
		for _, destination := range destinations {
			if _, ok := answers[destination]; ok {
				continue
			}
			txID := stun.NewTxID()
			pending[txID] = destination
			if err := c.sendDirectOnlyPoolProbe(pc, stun.Request(txID), destination); err != nil {
				c.dlogf("[v1] magicsock: direct-only NAT pool probe to %v: %v", destination, err)
			}
		}
	}
	send()
	retransmit := time.NewTicker(directOnlyPoolProbeRetransmit)
	defer retransmit.Stop()
	for sends := 1; len(answers) < len(destinations); {
		select {
		case <-ctx.Done():
			return directOnlyPoolAnswers(destinations, answers)
		case <-readerDone:
			return directOnlyPoolAnswers(destinations, answers)
		case <-retransmit.C:
			if sends < 3 {
				send()
				sends++
			}
		case packet := <-received:
			txID, mapped, err := stun.ParseResponse(packet.payload)
			if err != nil {
				continue
			}
			destination, ok := pending[txID]
			source := netip.AddrPortFrom(packet.source.Addr().Unmap(), packet.source.Port())
			if !ok || destination != source {
				continue
			}
			if _, answered := answers[destination]; !answered {
				answers[destination] = netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port())
			}
		}
	}
	return directOnlyPoolAnswers(destinations, answers)
}

// directOnlyPoolAnswers returns the answers in destination order.
func directOnlyPoolAnswers(destinations []netip.AddrPort, answers map[netip.AddrPort]netip.AddrPort) []directOnlyPoolObservation {
	observations := make([]directOnlyPoolObservation, 0, len(answers))
	for _, destination := range destinations {
		if mapped, ok := answers[destination]; ok {
			observations = append(observations, directOnlyPoolObservation{destination: destination, mapped: mapped})
		}
	}
	return observations
}

// directOnlyMainObservations returns the main socket's per-destination IPv4
// observations from a report of the transient STUN-only descriptor, whose
// region i is direct-only STUN destination i-1.
func (c *Conn) directOnlyMainObservations(report *netcheck.Report) []directOnlyPoolObservation {
	var observations []directOnlyPoolObservation
	for index, destination := range c.directSTUNEndpoints {
		if mapped, ok := report.GlobalV4ByRegion[index+1]; ok {
			observations = append(observations, directOnlyPoolObservation{destination: destination, mapped: mapped})
		}
	}
	return observations
}
