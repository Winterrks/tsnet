// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/net/netcheck"
)

func TestValidDirectOnlySTUNEndpoints(t *testing.T) {
	first := netip.MustParseAddrPort("192.0.2.1:3478")
	second := netip.MustParseAddrPort("[2001:db8::1]:19302")
	full := make([]netip.AddrPort, 0, MaxDirectSTUNEndpoints+1)
	for index := range MaxDirectSTUNEndpoints + 1 {
		full = append(full, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 3478))
	}
	tests := []struct {
		name      string
		endpoints []netip.AddrPort
		want      bool
	}{
		{name: "one", endpoints: []netip.AddrPort{first}, want: true},
		{name: "mixed families", endpoints: []netip.AddrPort{first, second}, want: true},
		{name: "maximum", endpoints: full[:MaxDirectSTUNEndpoints], want: true},
		{name: "nil"},
		{name: "empty", endpoints: []netip.AddrPort{}},
		{name: "over maximum", endpoints: full},
		{name: "duplicate", endpoints: []netip.AddrPort{first, second, first}},
		{name: "zero port", endpoints: []netip.AddrPort{first, netip.MustParseAddrPort("192.0.2.2:0")}},
		{name: "overlay", endpoints: []netip.AddrPort{netip.MustParseAddrPort("100.64.0.1:3478")}},
		{name: "DERP magic IP", endpoints: []netip.AddrPort{netip.MustParseAddrPort("127.3.3.40:3478")}},
		{name: "IPv4-mapped IPv6", endpoints: []netip.AddrPort{netip.MustParseAddrPort("[::ffff:192.0.2.1]:3478")}},
		{name: "multicast", endpoints: []netip.AddrPort{netip.MustParseAddrPort("224.0.0.1:3478")}},
		{name: "unspecified", endpoints: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:3478")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidDirectOnlySTUNEndpoints(tt.endpoints); got != tt.want {
				t.Fatalf("ValidDirectOnlySTUNEndpoints(%v) = %v, want %v", tt.endpoints, got, tt.want)
			}
		})
	}
}

func TestDirectOnlySTUNMapPutsEachDestinationInItsOwnSTUNOnlyRegion(t *testing.T) {
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:3478"),
		netip.MustParseAddrPort("198.51.100.2:19302"),
		netip.MustParseAddrPort("[2001:db8::3]:19302"),
	}
	dm := directOnlySTUNMap(endpoints)
	if !dm.OmitDefaultRegions || len(dm.Regions) != len(endpoints) {
		t.Fatalf("map = %+v, want %d regions without defaults", dm, len(endpoints))
	}
	names := make(map[string]bool)
	for index, endpoint := range endpoints {
		region := dm.Regions[index+1]
		if region == nil || region.RegionID != index+1 || len(region.Nodes) != 1 {
			t.Fatalf("region %d = %+v, want one node", index+1, region)
		}
		node := region.Nodes[0]
		if !node.STUNOnly || node.RegionID != region.RegionID || node.STUNPort != int(endpoint.Port()) ||
			node.DERPPort != 0 || node.STUNTestIP != "" || names[node.Name] {
			t.Fatalf("region %d node = %+v", index+1, node)
		}
		names[node.Name] = true
		wantV4, wantV6 := "none", "none"
		if endpoint.Addr().Is4() {
			wantV4 = endpoint.Addr().String()
		} else {
			wantV6 = endpoint.Addr().String()
		}
		if node.IPv4 != wantV4 || node.IPv6 != wantV6 {
			t.Fatalf("region %d node addresses = %q/%q, want %q/%q", index+1, node.IPv4, node.IPv6, wantV4, wantV6)
		}
	}
}

func TestDirectOnlyMainObservationsNameEachRegionsDestination(t *testing.T) {
	c := &Conn{directSTUNEndpoints: []netip.AddrPort{
		netip.MustParseAddrPort("9.9.9.1:3478"),
		netip.MustParseAddrPort("9.9.9.2:19302"),
		netip.MustParseAddrPort("[2606:4700::1]:3478"),
	}}
	report := &netcheck.Report{GlobalV4ByRegion: map[int]netip.AddrPort{
		1: netip.MustParseAddrPort("45.0.0.177:41641"),
		2: netip.MustParseAddrPort("45.0.0.185:41641"),
		9: netip.MustParseAddrPort("46.0.0.1:41641"), // not a listed region
	}}
	want := []directOnlyPoolObservation{
		{destination: c.directSTUNEndpoints[0], mapped: netip.MustParseAddrPort("45.0.0.177:41641")},
		{destination: c.directSTUNEndpoints[1], mapped: netip.MustParseAddrPort("45.0.0.185:41641")},
	}
	if got := c.directOnlyMainObservations(report); !slices.Equal(got, want) {
		t.Fatalf("main observations = %+v, want %+v", got, want)
	}
}
