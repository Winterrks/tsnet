// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package waifuscontrol provides a local, deterministic controlclient.Client
// for the public Waifus direct-only feasibility harness. It models only
// pair-scoped identities, direct endpoint generations, and directed local
// authorization. It intentionally contains no production coordination wire
// format or Worker credential logic.
package waifuscontrol

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
)

// Role is the node's position in a host-centered pair graph.
type Role uint8

const (
	RoleHost   Role = 1
	RoleRemote Role = 2
)

// Node is one immutable fake-control transport identity. Private keys are
// supplied by the test harness, just as the private helper supplies them in
// production; the Hub never generates replacement keys.
type Node struct {
	Name            string
	Role            Role
	NodeID          tailcfg.NodeID
	StableID        tailcfg.StableNodeID
	Address         netip.Prefix
	NodePrivateKey  key.NodePrivate
	DiscoPrivateKey key.DiscoPrivate
}

// PublicNodeKey returns n's WireGuard public key.
func (n Node) PublicNodeKey() key.NodePublic { return n.NodePrivateKey.Public() }

// PublicDiscoKey returns n's discovery public key.
func (n Node) PublicDiscoKey() key.DiscoPublic { return n.DiscoPrivateKey.Public() }

type nodeState struct {
	config     Node
	client     *Client
	loggedIn   bool
	paused     bool
	endpoints  []netip.AddrPort
	generation uint64
	lastMap    *netmap.NetworkMap
	deliveries uint64
}

// Hub serializes fake coordination updates without ever invoking a
// LocalBackend observer while holding its own mutex. That is required because
// LocalBackend invokes Client methods while holding its mutex.
type Hub struct {
	mu          sync.Mutex
	nodes       map[string]*nodeState
	allowed     map[string]map[string]bool
	connected   bool
	update      chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
	clientID    atomic.Int64
	protocolErr error
}

// New constructs and starts a local fake coordination hub.
func New(nodes ...Node) (*Hub, error) {
	h := &Hub{
		nodes:     make(map[string]*nodeState, len(nodes)),
		allowed:   make(map[string]map[string]bool, len(nodes)),
		connected: true,
		update:    make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	seenNodeKeys := make(map[key.NodePublic]bool, len(nodes))
	seenDiscoKeys := make(map[key.DiscoPublic]bool, len(nodes))
	seenAddresses := make(map[netip.Prefix]bool, len(nodes))
	seenNodeIDs := make(map[tailcfg.NodeID]bool, len(nodes))
	seenStableIDs := make(map[tailcfg.StableNodeID]bool, len(nodes))
	for _, node := range nodes {
		if err := validateNode(node); err != nil {
			return nil, err
		}
		if _, ok := h.nodes[node.Name]; ok {
			return nil, fmt.Errorf("duplicate node name %q", node.Name)
		}
		if seenNodeKeys[node.PublicNodeKey()] || seenDiscoKeys[node.PublicDiscoKey()] ||
			seenAddresses[node.Address] || seenNodeIDs[node.NodeID] || seenStableIDs[node.StableID] {
			return nil, errors.New("duplicate fake-control identity")
		}
		seenNodeKeys[node.PublicNodeKey()] = true
		seenDiscoKeys[node.PublicDiscoKey()] = true
		seenAddresses[node.Address] = true
		seenNodeIDs[node.NodeID] = true
		seenStableIDs[node.StableID] = true
		h.nodes[node.Name] = &nodeState{config: node}
		h.allowed[node.Name] = make(map[string]bool)
	}
	h.wg.Add(1)
	go h.run()
	return h, nil
}

func validateNode(node Node) error {
	switch {
	case node.Name == "":
		return errors.New("fake-control node name is required")
	case node.Role != RoleHost && node.Role != RoleRemote:
		return fmt.Errorf("fake-control node %q has invalid role %d", node.Name, node.Role)
	case node.NodeID == 0 || node.StableID == "":
		return fmt.Errorf("fake-control node %q is missing stable identifiers", node.Name)
	case node.NodePrivateKey.IsZero() || node.DiscoPrivateKey.IsZero():
		return fmt.Errorf("fake-control node %q is missing private transport identity", node.Name)
	case !node.Address.IsValid() || !node.Address.IsSingleIP() || !tsaddr.IsTailscaleIP(node.Address.Addr()):
		return fmt.Errorf("fake-control node %q has invalid userspace address %v", node.Name, node.Address)
	}
	return nil
}

// Close shuts down the fake coordinator. It does not shut down clients; their
// embedding LocalBackends own that lifecycle.
func (h *Hub) Close() {
	h.closeOnce.Do(func() { close(h.done) })
	h.wg.Wait()
}

// ApprovePair adds the two directed edges for one host/remote pair and queues
// full pair-isolated maps when coordination is connected.
func (h *Hub) ApprovePair(host, remote string) error {
	h.mu.Lock()
	hostState, hostOK := h.nodes[host]
	remoteState, remoteOK := h.nodes[remote]
	if !hostOK || !remoteOK || hostState.config.Role != RoleHost || remoteState.config.Role != RoleRemote {
		h.mu.Unlock()
		return fmt.Errorf("invalid host/remote pair %q/%q", host, remote)
	}
	h.allowed[host][remote] = true
	h.allowed[remote][host] = true
	h.mu.Unlock()
	h.requestPublish()
	return nil
}

// DenyLocal changes only viewer's local authorization decision. It does not
// publish a coordination update, making it suitable for offline-revocation
// tests that call LocalBackend.RefreshWaifusPeerAuthorizations.
func (h *Hub) DenyLocal(viewer, peer string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nodes[viewer] == nil || h.nodes[peer] == nil {
		return fmt.Errorf("unknown fake-control edge %q/%q", viewer, peer)
	}
	h.allowed[viewer][peer] = false
	return nil
}

// Authorizer returns the directed local authorization callback for viewer.
func (h *Hub) Authorizer(viewer string) ipnlocal.WaifusPeerAuthorizer {
	return func(identity ipnlocal.WaifusPeerIdentity) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for name, state := range h.nodes {
			if !h.allowed[viewer][name] {
				continue
			}
			node := state.config
			if identity.NodeID == node.NodeID && identity.StableID == node.StableID &&
				identity.NodeKey == node.PublicNodeKey() && identity.DiscoKey == node.PublicDiscoKey() &&
				identity.Address == node.Address {
				return true
			}
		}
		return false
	}
}

// SetConnected controls only map publication. Clients and their existing
// direct paths remain alive while false.
func (h *Hub) SetConnected(connected bool) {
	h.mu.Lock()
	h.connected = connected
	h.mu.Unlock()
	if connected {
		h.requestPublish()
	}
}

// Publish queues a full valid-map refresh when coordination is connected.
func (h *Hub) Publish() { h.requestPublish() }

// Factory returns the exact controlclient construction closure for name.
func (h *Hub) Factory(name string) func(controlclient.Options) (controlclient.Client, error) {
	return func(opts controlclient.Options) (controlclient.Client, error) {
		return h.NewClient(name, opts)
	}
}

// NewClient attaches one control client generation to name.
func (h *Hub) NewClient(name string, opts controlclient.Options) (*Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.nodes[name]
	if state == nil {
		return nil, fmt.Errorf("unknown fake-control node %q", name)
	}
	if opts.Observer == nil {
		return nil, errors.New("fake-control observer is required")
	}
	if opts.DiscoPublicKey != state.config.PublicDiscoKey() {
		return nil, fmt.Errorf("fake-control discovery key mismatch for %q", name)
	}
	if persisted, ok := opts.Persist.PublicNodeKeyOK(); ok && persisted != state.config.PublicNodeKey() {
		return nil, fmt.Errorf("fake-control stored node key mismatch for %q", name)
	}
	client := &Client{
		hub:      h,
		name:     name,
		opts:     opts,
		clientID: h.clientID.Add(1),
	}
	state.client = client
	state.loggedIn = false
	state.paused = opts.StartPaused
	return client, nil
}

// LastMap returns a detached copy of the last map delivered to name.
func (h *Hub) LastMap(name string) *netmap.NetworkMap {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.nodes[name]
	if state == nil || state.lastMap == nil {
		return nil
	}
	return cloneMap(state.lastMap)
}

// EndpointGeneration returns the number of distinct endpoint sets reported by
// name.
func (h *Hub) EndpointGeneration(name string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if state := h.nodes[name]; state != nil {
		return state.generation
	}
	return 0
}

// SetEndpoints replaces name's advertised direct candidates. It is used by
// feasibility fixtures for peers whose transport is intentionally absent or
// blocked, and follows the same bounded endpoint shape as a real client
// update.
func (h *Hub) SetEndpoints(name string, endpoints []netip.AddrPort) error {
	if len(endpoints) > 12 {
		return errors.New("too many fake-control endpoints")
	}
	addresses := append([]netip.AddrPort(nil), endpoints...)
	for _, endpoint := range addresses {
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
			return fmt.Errorf("invalid fake-control endpoint %v", endpoint)
		}
	}
	slices.SortFunc(addresses, netip.AddrPort.Compare)
	if len(slices.Compact(addresses)) != len(addresses) {
		return errors.New("duplicate fake-control endpoint")
	}

	h.mu.Lock()
	state := h.nodes[name]
	if state == nil {
		h.mu.Unlock()
		return fmt.Errorf("unknown fake-control node %q", name)
	}
	changed := !slices.Equal(state.endpoints, addresses)
	if changed {
		state.endpoints = addresses
		state.generation++
	}
	h.mu.Unlock()
	if changed {
		h.requestPublish()
	}
	return nil
}

// DeliveryCount returns the number of full maps delivered to name.
func (h *Hub) DeliveryCount(name string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if state := h.nodes[name]; state != nil {
		return state.deliveries
	}
	return 0
}

// WaitForMap waits until name has received at least deliveries maps and the
// latest map satisfies predicate. A nil predicate accepts any map.
func (h *Hub) WaitForMap(ctx context.Context, name string, deliveries uint64, predicate func(*netmap.NetworkMap) bool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		h.mu.Lock()
		state := h.nodes[name]
		var nm *netmap.NetworkMap
		var count uint64
		if state != nil {
			count = state.deliveries
			if state.lastMap != nil {
				nm = cloneMap(state.lastMap)
			}
		}
		h.mu.Unlock()
		if count >= deliveries && nm != nil && (predicate == nil || predicate(nm)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ProtocolError reports an invariant violation observed through a Client
// method, such as an attempted discovery-key replacement.
func (h *Hub) ProtocolError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.protocolErr
}

// InjectMap delivers one caller-supplied full map using the node's valid local
// identity envelope. It exists only for malicious-map feasibility fixtures.
func (h *Hub) InjectMap(name string, nm *netmap.NetworkMap) error {
	h.mu.Lock()
	state := h.nodes[name]
	if state == nil || state.client == nil || !state.loggedIn {
		h.mu.Unlock()
		return fmt.Errorf("fake-control node %q has no logged-in client", name)
	}
	client := state.client
	identity := &persist.Persist{
		PrivateNodeKey: state.config.NodePrivateKey,
		NodeID:         state.config.StableID,
	}
	h.mu.Unlock()
	client.opts.Observer.SetControlClientStatus(client, controlclient.Status{
		LoggedIn:  true,
		InMapPoll: true,
		NetMap:    nm,
		Persist:   identity.View(),
	})
	return nil
}

func (h *Hub) run() {
	defer h.wg.Done()
	for {
		select {
		case <-h.done:
			return
		case <-h.update:
			h.publish()
		}
	}
}

func (h *Hub) requestPublish() {
	select {
	case h.update <- struct{}{}:
	default:
	}
}

type delivery struct {
	client *Client
	status controlclient.Status
	netMap *netmap.NetworkMap
}

func (h *Hub) publish() {
	h.mu.Lock()
	if !h.connected {
		h.mu.Unlock()
		return
	}
	var deliveries []delivery
	for name, state := range h.nodes {
		if state.client == nil || !state.loggedIn || state.paused {
			continue
		}
		nm := h.mapForLocked(name)
		identity := &persist.Persist{
			PrivateNodeKey: state.config.NodePrivateKey,
			NodeID:         state.config.StableID,
		}
		deliveries = append(deliveries, delivery{
			client: state.client,
			status: controlclient.Status{
				LoggedIn:  true,
				InMapPoll: true,
				NetMap:    nm,
				Persist:   identity.View(),
			},
			netMap: nm,
		})
	}
	h.mu.Unlock()

	for _, delivery := range deliveries {
		delivery.client.opts.Observer.SetControlClientStatus(delivery.client, delivery.status)
		h.mu.Lock()
		state := h.nodes[delivery.client.name]
		if state != nil && state.client == delivery.client {
			state.lastMap = cloneMap(delivery.netMap)
			state.deliveries++
		}
		h.mu.Unlock()
	}
}

func (h *Hub) mapForLocked(viewer string) *netmap.NetworkMap {
	self := h.nodes[viewer]
	nm := &netmap.NetworkMap{
		SelfNode: nodeView(self),
		NodeKey:  self.config.PublicNodeKey(),
	}
	for name, allowed := range h.allowed[viewer] {
		if allowed {
			nm.Peers = append(nm.Peers, nodeView(h.nodes[name]))
		}
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return nm
}

func nodeView(state *nodeState) tailcfg.NodeView {
	node := &tailcfg.Node{
		ID:                state.config.NodeID,
		StableID:          state.config.StableID,
		Key:               state.config.PublicNodeKey(),
		DiscoKey:          state.config.PublicDiscoKey(),
		Addresses:         []netip.Prefix{state.config.Address},
		AllowedIPs:        []netip.Prefix{state.config.Address},
		Endpoints:         append([]netip.AddrPort(nil), state.endpoints...),
		MachineAuthorized: true,
		Cap:               tailcfg.CurrentCapabilityVersion,
		Hostinfo:          new(tailcfg.Hostinfo).View(),
	}
	return node.View()
}

func cloneMap(nm *netmap.NetworkMap) *netmap.NetworkMap {
	if nm == nil {
		return nil
	}
	clone := *nm
	clone.Peers = append([]tailcfg.NodeView(nil), nm.Peers...)
	return &clone
}

// Client is a comparable fake controlclient.Client.
type Client struct {
	hub          *Hub
	name         string
	opts         controlclient.Options
	clientID     int64
	shutdownOnce sync.Once
}

func (c *Client) Shutdown() {
	c.shutdownOnce.Do(func() {
		c.hub.mu.Lock()
		if state := c.hub.nodes[c.name]; state != nil && state.client == c {
			state.client = nil
			state.loggedIn = false
		}
		c.hub.mu.Unlock()
		if c.opts.Shutdown != nil {
			c.opts.Shutdown()
		}
	})
}

func (c *Client) Login(controlclient.LoginFlags) {
	c.hub.mu.Lock()
	if state := c.hub.nodes[c.name]; state != nil && state.client == c {
		state.loggedIn = true
	}
	c.hub.mu.Unlock()
	c.hub.requestPublish()
}

func (c *Client) Logout(context.Context) error {
	c.hub.mu.Lock()
	if state := c.hub.nodes[c.name]; state != nil && state.client == c {
		state.loggedIn = false
	}
	c.hub.mu.Unlock()
	return nil
}

func (c *Client) SetPaused(paused bool) {
	c.hub.mu.Lock()
	changed := false
	if state := c.hub.nodes[c.name]; state != nil && state.client == c {
		if state.paused != paused {
			state.paused = paused
			changed = true
		}
	}
	c.hub.mu.Unlock()
	if changed && !paused {
		c.hub.requestPublish()
	}
}

func (*Client) AuthCantContinue() bool        { return false }
func (*Client) SetHostinfo(*tailcfg.Hostinfo) {}
func (*Client) SetNetInfo(*tailcfg.NetInfo)   {}
func (*Client) SetTKAHead(string)             {}
func (*Client) SetIPForwardingBroken(bool)    {}
func (c *Client) ClientID() int64             { return c.clientID }

func (c *Client) UpdateEndpoints(endpoints []tailcfg.Endpoint) {
	addresses := make([]netip.AddrPort, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Addr.IsValid() {
			addresses = append(addresses, endpoint.Addr)
		}
	}
	if len(addresses) > 12 {
		addresses = addresses[:12]
	}
	slices.SortFunc(addresses, netip.AddrPort.Compare)
	addresses = slices.Compact(addresses)

	c.hub.mu.Lock()
	state := c.hub.nodes[c.name]
	changed := false
	if state != nil && state.client == c && !slices.Equal(state.endpoints, addresses) {
		state.endpoints = append([]netip.AddrPort(nil), addresses...)
		state.generation++
		changed = true
	}
	c.hub.mu.Unlock()
	if changed {
		c.hub.requestPublish()
	}
}

func (c *Client) SetDiscoPublicKey(discoKey key.DiscoPublic) {
	c.hub.mu.Lock()
	defer c.hub.mu.Unlock()
	state := c.hub.nodes[c.name]
	if state != nil && discoKey != state.config.PublicDiscoKey() && c.hub.protocolErr == nil {
		c.hub.protocolErr = fmt.Errorf("fake-control node %q attempted discovery-key replacement", c.name)
	}
}
