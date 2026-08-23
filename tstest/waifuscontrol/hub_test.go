// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package waifuscontrol

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

func TestHubPublishesOnlyPairIsolatedViews(t *testing.T) {
	host := testNode("host", RoleHost, 1, "100.64.0.1/32")
	remoteA := testNode("remote-a", RoleRemote, 2, "100.64.0.2/32")
	remoteB := testNode("remote-b", RoleRemote, 3, "100.64.0.3/32")
	hub, err := New(host, remoteA, remoteB)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(hub.Close)
	if err := hub.ApprovePair(host.Name, remoteA.Name); err != nil {
		t.Fatalf("ApprovePair A: %v", err)
	}
	if err := hub.ApprovePair(host.Name, remoteB.Name); err != nil {
		t.Fatalf("ApprovePair B: %v", err)
	}

	observers := map[string]*testObserver{}
	clients := map[string]*Client{}
	for _, node := range []Node{host, remoteA, remoteB} {
		observer := new(testObserver)
		client, err := hub.NewClient(node.Name, controlclient.Options{
			DiscoPublicKey: node.PublicDiscoKey(),
			Observer:       observer,
		})
		if err != nil {
			t.Fatalf("NewClient(%s): %v", node.Name, err)
		}
		observers[node.Name] = observer
		clients[node.Name] = client
		client.Login(controlclient.LoginDefault)
		client.UpdateEndpoints([]tailcfg.Endpoint{{Addr: netip.MustParseAddrPort("127.0.0.1:41641")}})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, node := range []Node{host, remoteA, remoteB} {
		if err := hub.WaitForMap(ctx, node.Name, 1, nil); err != nil {
			t.Fatalf("WaitForMap(%s): %v", node.Name, err)
		}
	}

	hostMap := hub.LastMap(host.Name)
	if len(hostMap.Peers) != 2 {
		t.Fatalf("host peers = %d, want 2", len(hostMap.Peers))
	}
	for _, remote := range []Node{remoteA, remoteB} {
		nm := hub.LastMap(remote.Name)
		if len(nm.Peers) != 1 || nm.Peers[0].Key() != host.PublicNodeKey() {
			t.Fatalf("%s peer view = %v, want host only", remote.Name, nm.Peers)
		}
		otherKey := remoteA.PublicNodeKey()
		if remote.Name == remoteA.Name {
			otherKey = remoteB.PublicNodeKey()
		}
		if mapContainsKey(nm, otherKey) {
			t.Fatalf("%s learned the other remote key", remote.Name)
		}
	}

	hub.SetConnected(false)
	if err := hub.DenyLocal(host.Name, remoteA.Name); err != nil {
		t.Fatalf("DenyLocal: %v", err)
	}
	if hub.Authorizer(host.Name)(identityFor(remoteA)) {
		t.Fatal("host authorizer retained locally revoked remote A")
	}
	if !hub.Authorizer(host.Name)(identityFor(remoteB)) {
		t.Fatal("host authorizer disturbed remote B")
	}
	if len(hub.LastMap(host.Name).Peers) != 2 {
		t.Fatal("offline local denial unexpectedly arrived as a coordination map")
	}

	clients[host.Name].SetDiscoPublicKey(key.NewDisco().Public())
	if hub.ProtocolError() == nil {
		t.Fatal("discovery-key replacement was not recorded")
	}
	for name, observer := range observers {
		if observer.count() == 0 {
			t.Fatalf("observer %s received no status", name)
		}
	}
}

type testObserver struct {
	mu       sync.Mutex
	statuses []controlclient.Status
}

func (o *testObserver) SetControlClientStatus(_ controlclient.Client, status controlclient.Status) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.statuses = append(o.statuses, status)
}

func (o *testObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.statuses)
}

func testNode(name string, role Role, id tailcfg.NodeID, address string) Node {
	return Node{
		Name:            name,
		Role:            role,
		NodeID:          id,
		StableID:        tailcfg.StableNodeID(name),
		Address:         netip.MustParsePrefix(address),
		NodePrivateKey:  key.NewNode(),
		DiscoPrivateKey: key.NewDisco(),
	}
}

func identityFor(node Node) ipnlocal.WaifusPeerIdentity {
	return ipnlocal.WaifusPeerIdentity{
		NodeID:   node.NodeID,
		StableID: node.StableID,
		NodeKey:  node.PublicNodeKey(),
		DiscoKey: node.PublicDiscoKey(),
		Address:  node.Address,
	}
}

func mapContainsKey(nm *netmap.NetworkMap, nodeKey key.NodePublic) bool {
	if nm.SelfNode.Valid() && nm.SelfNode.Key() == nodeKey {
		return true
	}
	for _, peer := range nm.Peers {
		if peer.Key() == nodeKey {
			return true
		}
	}
	return false
}
