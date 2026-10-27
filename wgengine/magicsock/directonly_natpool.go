// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/netcheck"
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
	// seen maps each remembered public address to when it was last observed.
	seen map[netip.Addr]time.Time
	// learned reports that a learning round on this link got an answer.
	learned bool
	// lastRound is when the latest learning round on this link started.
	lastRound time.Time
	// crossAddressPort reports that one socket on this link observed two
	// pool addresses with the same mapped port: the NAT keeps a socket's
	// port across the addresses it chooses.
	crossAddressPort bool
}

// directOnlyNATPoolAddress reports whether addr may be remembered as a NAT
// public address: a global unicast, non-private IPv4 outside the Tailscale
// ranges.
func directOnlyNATPoolAddress(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !tsaddr.IsTailscaleIP(addr)
}

// resetLocked forgets everything learned and records link as the current
// network.
func (p *directOnlyNATPool) resetLocked(link string) {
	p.link = link
	p.generation++
	p.seen = nil
	p.learned = false
	p.lastRound = time.Time{}
	p.crossAddressPort = false
}

// reset forgets the pool, for example after a rebind or network loss.
func (p *directOnlyNATPool) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetLocked(p.link)
}

// expireLocked drops addresses not observed within the lifetime.
func (p *directOnlyNATPool) expireLocked(now time.Time) {
	for addr, at := range p.seen {
		if now.Sub(at) > directOnlyNATPoolLifetime {
			delete(p.seen, addr)
		}
	}
}

// beginRefresh switches the pool to link, clearing it if the network
// changed, and returns the generation that this refresh's observations
// belong to. It also reports whether this refresh should run a learning
// round: on a new network, until a round has been answered, and whenever a
// remembered address has gone unobserved for the relearn age, but at most
// once per round interval.
func (p *directOnlyNATPool) beginRefresh(now time.Time, link string) (generation uint64, learn bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if link != p.link || p.generation == 0 {
		p.resetLocked(link)
	}
	p.expireLocked(now)
	due := !p.learned
	for _, at := range p.seen {
		due = due || now.Sub(at) >= directOnlyNATPoolRelearnAge
	}
	if !due || !p.lastRound.IsZero() && now.Sub(p.lastRound) < directOnlyPoolRoundInterval {
		return p.generation, false
	}
	p.lastRound = now
	return p.generation, true
}

// observe records the mapped addresses one socket saw, and whether the
// observations show the NAT keeping the socket's port across pool addresses.
// Observations from an earlier generation are ignored.
func (p *directOnlyNATPool) observe(now time.Time, generation uint64, mapped []netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation {
		return
	}
	addrsByPort := make(map[uint16]netip.Addr)
	for _, ap := range mapped {
		addr := ap.Addr().Unmap()
		if !directOnlyNATPoolAddress(addr) {
			continue
		}
		if first, ok := addrsByPort[ap.Port()]; !ok {
			addrsByPort[ap.Port()] = addr
		} else if first != addr {
			p.crossAddressPort = true
		}
		if p.seen == nil {
			p.seen = make(map[netip.Addr]time.Time)
		}
		p.seen[addr] = now
	}
	p.expireLocked(now)
	for len(p.seen) > directOnlyNATPoolMax {
		var oldest netip.Addr
		var oldestAt time.Time
		for addr, at := range p.seen {
			if !oldest.IsValid() || at.Before(oldestAt) || at.Equal(oldestAt) && addr.Less(oldest) {
				oldest, oldestAt = addr, at
			}
		}
		delete(p.seen, oldest)
	}
}

// markLearned records that a learning round of generation got an answer.
func (p *directOnlyNATPool) markLearned(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation == p.generation {
		p.learned = true
	}
}

// snapshot returns the remembered addresses, sorted, and whether the NAT was
// seen keeping a port across pool addresses on this network.
func (p *directOnlyNATPool) snapshot(now time.Time) (addrs []netip.Addr, crossAddressPort bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	for addr := range p.seen {
		addrs = append(addrs, addr)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return addrs, p.crossAddressPort
}

// directOnlyPoolPort returns the mapped port to pair with every remembered
// pool address, given the main socket's report and local port. Every IPv4
// observation of the main socket must share one mapped port, and either that
// port is the local port (a port-preserving NAT) or some socket on this
// network saw two pool addresses with one port (the NAT keeps the port across
// the addresses it chooses). Otherwise the port another pool address would
// carry is unknown and no pool candidate is derived.
func directOnlyPoolPort(nr *netcheck.Report, localPort uint16, crossAddressPort bool) (uint16, bool) {
	if nr == nil || len(nr.GlobalV4Counters) == 0 {
		return 0, false
	}
	var port uint16
	addrs := make(map[netip.Addr]bool, len(nr.GlobalV4Counters))
	for ap := range nr.GlobalV4Counters {
		if port != 0 && ap.Port() != port {
			return 0, false
		}
		port = ap.Port()
		addrs[ap.Addr()] = true
	}
	if port == 0 {
		return 0, false
	}
	if port == localPort || crossAddressPort || len(addrs) >= 2 {
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
	port, ok := directOnlyPoolPort(nr, c.LocalPort(), crossAddressPort)
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
			mapped := c.probeDirectOnlyPoolSocket(ctx, destinations)
			c.directOnlyNATPool.observe(time.Now(), generation, mapped)
			answered[index] = len(mapped) != 0
		})
	}
	wg.Wait()
	return slices.Contains(answered, true)
}

// probeDirectOnlyPoolSocket opens one extra UDP socket, sends a binding
// request to each destination (retransmitting unanswered ones at most twice),
// and returns the mapped addresses from responses that match a request's
// transaction ID and destination. The socket is closed before it returns.
func (c *Conn) probeDirectOnlyPoolSocket(ctx context.Context, destinations []netip.AddrPort) []netip.AddrPort {
	pc, err := c.listenPacket("udp4", 0)
	if err != nil {
		c.dlogf("[v1] magicsock: direct-only NAT pool probe socket: %v", err)
		return nil
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
		for {
			n, source, err := pc.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
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

// directOnlyPoolAnswers returns the answered mapped addresses in destination
// order.
func directOnlyPoolAnswers(destinations []netip.AddrPort, answers map[netip.AddrPort]netip.AddrPort) []netip.AddrPort {
	mapped := make([]netip.AddrPort, 0, len(answers))
	for _, destination := range destinations {
		if ap, ok := answers[destination]; ok {
			mapped = append(mapped, ap)
		}
	}
	return mapped
}
