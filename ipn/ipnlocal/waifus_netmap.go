// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"net/netip"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

var (
	// ErrWaifusNetworkMap reports a network map that exceeds the pair-only
	// Waifus transport contract.
	ErrWaifusNetworkMap = errors.New("network map violates Waifus pair-only policy")

	// ErrWaifusNetworkMapPolicy reports an invalid immutable validator policy.
	ErrWaifusNetworkMapPolicy = errors.New("invalid Waifus network map policy")
)

// WaifusNodeRole identifies which side of the host-centered pair graph owns a
// LocalBackend. A host may see independently approved remotes; a remote may
// see at most its one selected host.
type WaifusNodeRole uint8

const (
	WaifusNodeRoleHost   WaifusNodeRole = 1
	WaifusNodeRoleRemote WaifusNodeRole = 2
)

// WaifusPeerIdentity is the complete peer identity tuple the private helper
// must approve before it can enter an embedded network map.
type WaifusPeerIdentity struct {
	NodeID   tailcfg.NodeID
	StableID tailcfg.StableNodeID
	NodeKey  key.NodePublic
	DiscoKey key.DiscoPublic
	Address  netip.Prefix
}

// WaifusPeerAuthorizer reports whether identity is a currently approved pair
// edge. It is called with the LocalBackend mutex held and must not block or
// call back into the LocalBackend.
type WaifusPeerAuthorizer func(identity WaifusPeerIdentity) bool

type waifusNetworkMapValidator struct {
	role            WaifusNodeRole
	applicationPort uint16
	authorizePeer   WaifusPeerAuthorizer
	identities      map[key.NodePublic]WaifusPeerIdentity
	nodeIDOwners    map[tailcfg.NodeID]key.NodePublic
	stableIDOwners  map[tailcfg.StableNodeID]key.NodePublic
	discoKeyOwners  map[key.DiscoPublic]key.NodePublic
	addressOwners   map[netip.Prefix]key.NodePublic
}

func newWaifusNetworkMapValidator(role WaifusNodeRole, applicationPort uint16, authorizePeer WaifusPeerAuthorizer) (*waifusNetworkMapValidator, error) {
	if role != WaifusNodeRoleHost && role != WaifusNodeRoleRemote {
		return nil, fmt.Errorf("%w: unknown role %d", ErrWaifusNetworkMapPolicy, role)
	}
	if authorizePeer == nil {
		return nil, fmt.Errorf("%w: peer authorizer is required", ErrWaifusNetworkMapPolicy)
	}
	if applicationPort == 0 {
		return nil, fmt.Errorf("%w: application port is required", ErrWaifusNetworkMapPolicy)
	}
	return &waifusNetworkMapValidator{
		role:            role,
		applicationPort: applicationPort,
		authorizePeer:   authorizePeer,
		identities:      make(map[key.NodePublic]WaifusPeerIdentity),
		nodeIDOwners:    make(map[tailcfg.NodeID]key.NodePublic),
		stableIDOwners:  make(map[tailcfg.StableNodeID]key.NodePublic),
		discoKeyOwners:  make(map[key.DiscoPublic]key.NodePublic),
		addressOwners:   make(map[netip.Prefix]key.NodePublic),
	}, nil
}

// Validate rejects generic tailnet state before any backend, engine, router,
// DNS, or peer-service mutation. Stable node/discovery keys and overlay
// addresses are pinned for this validator's lifetime; direct endpoints may
// change to support network mobility.
func (v *waifusNetworkMapValidator) Validate(nm *netmap.NetworkMap) error {
	if nm == nil {
		return v.invalid("nil map")
	}
	if !nm.SelfNode.Valid() {
		return v.invalid("missing self node")
	}
	if v.role == WaifusNodeRoleRemote && len(nm.Peers) > 1 {
		return v.invalid("remote view contains %d peers", len(nm.Peers))
	}
	if err := validateWaifusMapEnvelope(nm); err != nil {
		return err
	}

	self, err := validateWaifusNode(nm.SelfNode)
	if err != nil {
		return fmt.Errorf("%w: self node: %v", ErrWaifusNetworkMap, err)
	}
	if nm.NodeKey.IsZero() || nm.NodeKey != self.NodeKey {
		return v.invalid("map node key does not match self node")
	}

	identities := make([]WaifusPeerIdentity, 0, len(nm.Peers)+1)
	identities = append(identities, self)
	for i, peerView := range nm.Peers {
		peer, err := validateWaifusNode(peerView)
		if err != nil {
			return fmt.Errorf("%w: peer %d: %v", ErrWaifusNetworkMap, i, err)
		}
		if !v.authorizePeer(peer) {
			return v.invalid("peer %s is not an approved pair", peer.NodeKey.ShortString())
		}
		identities = append(identities, peer)
	}

	if err := v.validateIdentitySet(identities); err != nil {
		return err
	}
	for _, identity := range identities {
		v.identities[identity.NodeKey] = identity
		v.nodeIDOwners[identity.NodeID] = identity.NodeKey
		v.stableIDOwners[identity.StableID] = identity.NodeKey
		v.discoKeyOwners[identity.DiscoKey] = identity.NodeKey
		v.addressOwners[identity.Address] = identity.NodeKey
	}
	return nil
}

func validateWaifusMapEnvelope(nm *netmap.NetworkMap) error {
	switch {
	case nm.Cached:
		return fmt.Errorf("%w: cached maps are forbidden", ErrWaifusNetworkMap)
	case !nm.MachineKey.IsZero():
		return fmt.Errorf("%w: generic machine-key state is forbidden", ErrWaifusNetworkMap)
	case nm.DERPMap != nil:
		return fmt.Errorf("%w: DERP map is forbidden", ErrWaifusNetworkMap)
	case !waifusDNSConfigEmpty(nm.DNS):
		return fmt.Errorf("%w: DNS configuration is forbidden", ErrWaifusNetworkMap)
	case len(nm.PacketFilter) != 0 || nm.PacketFilterRules.Len() != 0:
		return fmt.Errorf("%w: control-provided packet filters are forbidden", ErrWaifusNetworkMap)
	case nm.SSHPolicy != nil:
		return fmt.Errorf("%w: SSH policy is forbidden", ErrWaifusNetworkMap)
	case nm.CollectServices:
		return fmt.Errorf("%w: service collection is forbidden", ErrWaifusNetworkMap)
	case len(nm.AllCaps) != 0:
		return fmt.Errorf("%w: tailnet capabilities are forbidden", ErrWaifusNetworkMap)
	case len(nm.DisplayMessages) != 0:
		return fmt.Errorf("%w: control display messages are forbidden", ErrWaifusNetworkMap)
	case nm.TKAEnabled || nm.TKAHead != (tka.AUMHash{}):
		return fmt.Errorf("%w: tailnet key authority is forbidden", ErrWaifusNetworkMap)
	case nm.Domain != "" || nm.DomainAuditLogID != "":
		return fmt.Errorf("%w: tailnet domain state is forbidden", ErrWaifusNetworkMap)
	case len(nm.UserProfiles) != 0:
		return fmt.Errorf("%w: user profiles are forbidden", ErrWaifusNetworkMap)
	}
	return nil
}

func validateWaifusNode(view tailcfg.NodeView) (WaifusPeerIdentity, error) {
	if !view.Valid() {
		return WaifusPeerIdentity{}, errors.New("invalid node")
	}
	node := view.AsStruct()
	if node.ID == 0 || node.StableID == "" {
		return WaifusPeerIdentity{}, errors.New("node ID and stable ID are required")
	}
	if node.Name != "" || node.User != 0 || node.Sharer != 0 || !node.Machine.IsZero() ||
		!node.Created.IsZero() || node.LastSeen != nil || node.Online != nil ||
		node.ComputedName != "" || node.ComputedNameWithHost != "" {
		return WaifusPeerIdentity{}, errors.New("generic owner, machine, name, or presence metadata is forbidden")
	}
	if node.Key.IsZero() || node.DiscoKey.IsZero() {
		return WaifusPeerIdentity{}, errors.New("node and discovery keys are required")
	}
	if len(node.Addresses) != 1 {
		return WaifusPeerIdentity{}, fmt.Errorf("addresses = %d, want exactly 1", len(node.Addresses))
	}
	address := node.Addresses[0]
	if !address.IsValid() || !address.IsSingleIP() || !tsaddr.IsTailscaleIP(address.Addr()) {
		return WaifusPeerIdentity{}, fmt.Errorf("invalid userspace address %v", address)
	}
	if len(node.AllowedIPs) != 1 || node.AllowedIPs[0] != address {
		return WaifusPeerIdentity{}, errors.New("allowed IPs contain a subnet, exit route, or cross-peer address")
	}
	if len(node.PrimaryRoutes) != 0 || len(node.ExitNodeDNSResolvers) != 0 {
		return WaifusPeerIdentity{}, errors.New("OS, subnet, or exit-node routes are forbidden")
	}
	if node.HomeDERP != 0 || node.LegacyDERPString != "" {
		return WaifusPeerIdentity{}, errors.New("DERP home is forbidden")
	}
	if !node.KeyExpiry.IsZero() || len(node.KeySignature) != 0 || node.Expired {
		return WaifusPeerIdentity{}, errors.New("key expiry or rotation state is forbidden")
	}
	if len(node.Capabilities) != 0 || len(node.CapMap) != 0 || len(node.Tags) != 0 {
		return WaifusPeerIdentity{}, errors.New("generic capabilities and tags are forbidden")
	}
	if node.UnsignedPeerAPIOnly || node.SelfNodeV4MasqAddrForThisPeer != nil || node.SelfNodeV6MasqAddrForThisPeer != nil {
		return WaifusPeerIdentity{}, errors.New("peer API and masquerade state are forbidden")
	}
	if node.IsWireGuardOnly || node.IsJailed || node.DataPlaneAuditLogID != "" {
		return WaifusPeerIdentity{}, errors.New("generic WireGuard, jail, and audit state are forbidden")
	}
	if !node.MachineAuthorized {
		return WaifusPeerIdentity{}, errors.New("unauthorized node")
	}
	if node.Cap != tailcfg.CurrentCapabilityVersion {
		return WaifusPeerIdentity{}, fmt.Errorf("capability version = %d, want %d", node.Cap, tailcfg.CurrentCapabilityVersion)
	}
	if err := validateWaifusHostinfo(node.Hostinfo); err != nil {
		return WaifusPeerIdentity{}, err
	}
	if len(node.Endpoints) > 12 {
		return WaifusPeerIdentity{}, fmt.Errorf("direct endpoints = %d, want at most 12", len(node.Endpoints))
	}
	seenEndpoints := make(map[netip.AddrPort]bool, len(node.Endpoints))
	for _, endpoint := range node.Endpoints {
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() ||
			endpoint.Addr() == tailcfg.DerpMagicIPAddr || tsaddr.IsTailscaleIP(endpoint.Addr()) {
			return WaifusPeerIdentity{}, fmt.Errorf("forbidden direct endpoint %v", endpoint)
		}
		if seenEndpoints[endpoint] {
			return WaifusPeerIdentity{}, fmt.Errorf("duplicate direct endpoint %v", endpoint)
		}
		seenEndpoints[endpoint] = true
	}
	return WaifusPeerIdentity{
		NodeID:   node.ID,
		StableID: node.StableID,
		NodeKey:  node.Key,
		DiscoKey: node.DiscoKey,
		Address:  address,
	}, nil
}

func validateWaifusHostinfo(view tailcfg.HostinfoView) error {
	if !view.Valid() {
		return nil
	}
	hostinfo := view.AsStruct()
	if !hostinfo.Equal(new(tailcfg.Hostinfo)) {
		return errors.New("all generic host metadata and services are forbidden")
	}
	return nil
}

func (v *waifusNetworkMapValidator) validateIdentitySet(identities []WaifusPeerIdentity) error {
	nodeIDs := make(map[tailcfg.NodeID]bool, len(identities))
	stableIDs := make(map[tailcfg.StableNodeID]bool, len(identities))
	nodeKeys := make(map[key.NodePublic]bool, len(identities))
	discoKeys := make(map[key.DiscoPublic]bool, len(identities))
	addresses := make(map[netip.Prefix]bool, len(identities))
	for _, identity := range identities {
		if nodeIDs[identity.NodeID] || stableIDs[identity.StableID] || nodeKeys[identity.NodeKey] ||
			discoKeys[identity.DiscoKey] || addresses[identity.Address] {
			return v.invalid("duplicate node identity, key, or address")
		}
		nodeIDs[identity.NodeID] = true
		stableIDs[identity.StableID] = true
		nodeKeys[identity.NodeKey] = true
		discoKeys[identity.DiscoKey] = true
		addresses[identity.Address] = true

		if previous, ok := v.identities[identity.NodeKey]; ok && previous != identity {
			return v.invalid("identity drift for node %s", identity.NodeKey.ShortString())
		}
		if owner, ok := v.nodeIDOwners[identity.NodeID]; ok && owner != identity.NodeKey {
			return v.invalid("node ID %d was reassigned", identity.NodeID)
		}
		if owner, ok := v.stableIDOwners[identity.StableID]; ok && owner != identity.NodeKey {
			return v.invalid("stable ID %q was reassigned", identity.StableID)
		}
		if owner, ok := v.discoKeyOwners[identity.DiscoKey]; ok && owner != identity.NodeKey {
			return v.invalid("discovery key was reassigned")
		}
		if owner, ok := v.addressOwners[identity.Address]; ok && owner != identity.NodeKey {
			return v.invalid("userspace address %v was reassigned", identity.Address)
		}
	}
	return nil
}

func (v *waifusNetworkMapValidator) invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrWaifusNetworkMap, fmt.Sprintf(format, args...))
}

func waifusDNSConfigEmpty(config tailcfg.DNSConfig) bool {
	return len(config.Resolvers) == 0 && len(config.Routes) == 0 && len(config.FallbackResolvers) == 0 &&
		len(config.Domains) == 0 && !config.Proxied && len(config.Nameservers) == 0 &&
		len(config.CertDomains) == 0 && len(config.ExtraRecords) == 0 &&
		len(config.ExitNodeFilteredSet) == 0 && config.TempCorpIssue13969 == ""
}

func waifusPacketFilter(nm *netmap.NetworkMap, applicationPort uint16) []filter.Match {
	if nm == nil || !nm.SelfNode.Valid() || len(nm.Peers) == 0 {
		return nil
	}
	sources := make([]netip.Prefix, 0, len(nm.Peers))
	for _, peer := range nm.Peers {
		sources = append(sources, peer.Addresses().At(0))
	}
	return []filter.Match{{
		IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
		Srcs:    sources,
		Dsts: []filter.NetPortRange{{
			Net:   nm.SelfNode.Addresses().At(0),
			Ports: filter.PortRange{First: applicationPort, Last: applicationPort},
		}},
	}}
}
