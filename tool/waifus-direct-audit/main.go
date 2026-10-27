// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command waifus-direct-audit verifies the source-level choke points that make
// the Waifus direct-only policy fail closed. Runtime packet tests remain a
// separate gate; this command protects the structural assumptions behind them.
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	root, err := findRepositoryRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if failures := auditRepository(root); len(failures) != 0 {
		for _, failure := range failures {
			fmt.Fprintf(os.Stderr, "waifus direct-only audit: %v\n", failure)
		}
		os.Exit(1)
	}
	fmt.Println("waifus direct-only source audit: ok")
}

func findRepositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(dir, "go.mod"))
		if readErr == nil && strings.HasPrefix(string(data), "module tailscale.com\n") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("tailscale.com repository root not found")
		}
		dir = parent
	}
}

func auditRepository(root string) []error {
	var failures []error
	requireTaggedFile := func(directory, name string) {
		context := build.Default
		context.BuildTags = []string{"waifus_direct_only"}
		matched, err := context.MatchFile(filepath.Join(root, directory), name)
		if err != nil {
			failures = append(failures, fmt.Errorf("match %s/%s: %w", directory, name, err))
			return
		}
		if !matched {
			failures = append(failures, fmt.Errorf("%s/%s is not selected by waifus_direct_only", directory, name))
		}
	}
	requireTaggedFile("wgengine", "directonly_build.go")
	requireTaggedFile("wgengine/magicsock", "directonly_build.go")

	checks := []functionCheck{
		{
			file:   "wgengine/userspace.go",
			name:   "NewUserspaceEngine",
			before: "conf.DirectOnly && !directOnlyBuild",
			after:  "magicsock.NewConn",
		},
		{
			file:   "wgengine/userspace.go",
			name:   "Reconfig",
			before: "cfg.PrivateKey.Equal(e.directOnlyNodeKey)",
			after:  "e.tundev.SetWGConfig(cfg)",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "NewConn",
			before: "opts.DirectOnly && !directOnlyBuild",
			after:  "newConn",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "NewConn",
			before: "ValidDirectOnlySTUNEndpoints(opts.DirectSTUNEndpoints)",
			after:  "newConn",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "NewConn",
			before: "opts.ForceDiscoKey.IsZero()",
			after:  "newConn",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "NewConn",
			before: "opts.ForceNodeKey.IsZero()",
			after:  "newConn",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "SetPrivateKey",
			before: "privateKey.Equal(c.directOnlyNodeKey)",
			after:  "c.privateKey = newKey",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "RotateDiscoKey",
			before: "if c.directOnly",
			after:  "key.NewDisco()",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "updateNetInfo",
			before: "directOnlySTUNMap(c.directSTUNEndpoints)",
			after:  "c.netChecker.GetReport",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "sendUDPNetcheck",
			before: "c.directOnly && !c.directOnlySTUNEndpointAllowed(addr)",
			after:  "c.pconn4.WriteToUDPAddrPort",
		},
		{
			file:   "wgengine/magicsock/directonly_natpool.go",
			name:   "sendDirectOnlyPoolProbe",
			before: "!c.directOnlySTUNEndpointAllowed(addr)",
			after:  "pc.WriteToUDPAddrPort",
		},
		{
			file:   "wgengine/magicsock/directonly_natpool.go",
			name:   "probeDirectOnlyNATPool",
			before: "if !c.directOnly",
			after:  "c.probeDirectOnlyPoolSocket(",
		},
		{
			file:   "wgengine/magicsock/directonly_natpool.go",
			name:   "probeDirectOnlyPoolSocket",
			before: "pc.Close()",
			after:  "c.sendDirectOnlyPoolProbe(pc, stun.Request(txID), destination)",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "sendAddr",
			before: "if c.directOnly",
			after:  "derpWriteChanForRegion",
		},
		{
			file:   "wgengine/magicsock/derp.go",
			name:   "derpWriteChanForRegion",
			before: "if c.directOnly",
			after:  "derphttp.NewRegionClient",
		},
		{
			file:   "wgengine/magicsock/derp.go",
			name:   "setDERPMap",
			before: "if !c.directOnly",
			after:  "debugUseDERPAddr()",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "sendUDP",
			before: "c.directOnly && isGeneveEncap",
			after:  "sendUDPStd",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "sendUDPBatch",
			before: "c.directOnly && addr.vni.IsSet()",
			after:  "WriteWireGuardBatchTo",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "receiveIP",
			before: "c.directOnly && isGeneveEncap",
			after:  "geneve.Decode",
		},
		{
			file:   "wgengine/magicsock/magicsock.go",
			name:   "Open",
			before: "if !c.directOnly",
			after:  "c.receiveDERP",
		},
		{
			file:   "wgengine/magicsock/derp.go",
			name:   "receiveDERP",
			before: "if c.directOnly",
			after:  "range c.derpRecvCh",
		},
		{
			file:   "wgengine/magicsock/endpoint.go",
			name:   "addrForSendLocked",
			before: "if de.isDirectOnly()",
			after:  "de.derpAddr",
		},
		{
			file:   "wgengine/magicsock/relaymanager.go",
			name:   "relayManagerInputEvent",
			before: "if r.rejectDisabled()",
			after:  "r.init()",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "DirectOnly:          s.waifusControl != nil",
			after:  "Tun:                 s.Tun",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "ForceNodeKey:        forceNodeKey",
			after:  "ForceDiscoKey:       forceDiscoKey",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "ForceDiscoKey:       forceDiscoKey",
			after:  "Tun:                 s.Tun",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "ipnlocal.WithWaifusLocalIdentity(",
			after:  "ipnlocal.NewLocalBackend(",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "NewLocalBackend",
			before: "validateWaifusStoredIdentity(prefs.Persist, identity)",
			after:  "prefs.Persist = identity.Clone()",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "setControlClientStatusLocked",
			before: "b.waifusMapPolicy.ValidateControlStatus(",
			after:  "b.numClientStatusCalls.Add(1)",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "UpdateNetmapDelta",
			before: "if b.waifusRestricted",
			after:  "cn.UpdateNetmapDelta(muts)",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "UpdatePacketFilter",
			before: "if b.waifusRestricted",
			after:  "cn.setPacketFilter(rules, parsed)",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "UpdateUserProfiles",
			before: "if b.waifusRestricted",
			after:  "cn.mergeUserProfiles(profiles)",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "PatchDiscoKey",
			before: "if b.waifusRestricted",
			after:  "recordTSMPLearnedDisco(pub, disco)",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "updateFilterLocked",
			before: "waifusPacketFilter(netMap, b.waifusMapPolicy.applicationPort)",
			after:  "cn.PacketFilter()",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "WaifusPeerAddress",
			before: "b.waifusMapPolicy.authorizePeer(identity)",
			after:  "return identity.Address.Addr(), true",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "WaifusPeerKeyForAddress",
			before: "b.waifusMapPolicy.authorizePeer(identity)",
			after:  "return identity.NodeKey, true",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "RefreshWaifusPeerAuthorizations",
			before: "b.waifusMapPolicy.authorizePeer(identity)",
			after:  "b.setControlClientStatusLocked(",
		},
		{
			file:   "ipn/ipnlocal/local.go",
			name:   "initPeerAPIListenerLocked",
			before: "b.waifusRestricted",
			after:  "peerAPIServer{",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "startLogger",
			before: "if s.waifusControl != nil",
			after:  "logtail.NewLogger",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "ns.ProcessSubnets = s.waifusControl == nil",
			after:  "ns.Start(lb)",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "start",
			before: "if s.waifusControl != nil {\n\t\treturn nil\n\t}",
			after:  "localapi.NewHandler",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "Loopback",
			before: "if s.isWaifusMode()",
			after:  "socks5.Server{",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "registerListener",
			before: "if s.waifusControl != nil",
			after:  "s.listeners[key] = ln",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "registerListener",
			before: "host.Port() != s.waifusControl.applicationPort",
			after:  "s.listeners[key] = ln",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "DialWaifusPeer",
			before: "s.lb.WaifusPeerAddress(peerKey)",
			after:  "s.dialer.UserDial(ctx, \"tcp\", target)",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "DialWaifusPeer",
			before: "s.dialer.UserDial(ctx, \"tcp\", target)",
			after:  "s.trackWaifusConnection(peerKey, connection)",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "RefreshWaifusPeerAuthorizations",
			before: "s.closeUnauthorizedWaifusConnections()",
			after:  "s.lb.RefreshWaifusPeerAuthorizations()",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "getTCPHandlerForFlow",
			before: "s.lb.WaifusPeerKeyForAddress(src.Addr())",
			after:  "ln.handle(s.trackWaifusConnection(peerKey, connection))",
		},
		{
			file:   "tsnet/tsnet.go",
			name:   "trackWaifusConnection",
			before: "s.lb.WaifusPeerAddress(peerKey)",
			after:  "return tracked",
		},
	}
	for _, check := range checks {
		if err := check.run(root); err != nil {
			failures = append(failures, err)
		}
	}

	magicsockDir := filepath.Join(root, "wgengine", "magicsock")
	entries, err := os.ReadDir(magicsockDir)
	if err != nil {
		failures = append(failures, err)
		return failures
	}
	constructorSites := 0
	listenSites := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(magicsockDir, entry.Name()))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		constructorSites += strings.Count(string(data), "derphttp.NewRegionClient(")
		listenSites += strings.Count(string(data), "c.listenPacket(")
	}
	if constructorSites != 1 {
		failures = append(failures, fmt.Errorf("DERP client constructor sites = %d, want exactly 1 guarded site", constructorSites))
	}
	// The rebinding main sockets and the direct-only NAT pool learning
	// sockets are the only UDP sockets magicsock opens.
	if listenSites != 2 {
		failures = append(failures, fmt.Errorf("magicsock socket open sites = %d, want exactly 2 (bindSocket and the guarded NAT pool probe)", listenSites))
	}
	if err := (functionForbids{
		file:      "wgengine/magicsock/directonly_natpool.go",
		name:      "probeDirectOnlyPoolSocket",
		forbidden: []string{"WriteTo", ".Write("},
	}).run(root); err != nil {
		failures = append(failures, err)
	}
	if err := auditRelayDependencies(root); err != nil {
		failures = append(failures, err)
	}
	return failures
}

func auditRelayDependencies(root string) error {
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goBinary, "list", "-deps", "-tags=waifus_direct_only", "./tsnet")
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("list tagged tsnet dependencies: %w", err)
	}

	allowedRelayPackages := map[string]bool{
		"tailscale.com/derp":                  true,
		"tailscale.com/derp/derpconst":        true,
		"tailscale.com/derp/derphttp":         true,
		"tailscale.com/net/udprelay/endpoint": true,
		"tailscale.com/net/udprelay/status":   true,
	}
	for dependency := range strings.Lines(string(output)) {
		dependency = strings.TrimSpace(dependency)
		if strings.HasPrefix(dependency, "tailscale.com/derp") ||
			strings.HasPrefix(dependency, "tailscale.com/net/udprelay") {
			if !allowedRelayPackages[dependency] {
				return fmt.Errorf("tagged tsnet gained forbidden relay dependency %q", dependency)
			}
		}
	}
	return nil
}

// functionForbids requires that a function's body never names a sink
// directly, so that it can reach that sink only through a guarded helper.
type functionForbids struct {
	file      string
	name      string
	forbidden []string
}

func (check functionForbids) run(root string) error {
	body, err := functionBody(root, check.file, check.name)
	if err != nil {
		return err
	}
	for _, forbidden := range check.forbidden {
		if strings.Contains(body, forbidden) {
			return fmt.Errorf("%s:%s names %q directly instead of its guarded helper", check.file, check.name, forbidden)
		}
	}
	return nil
}

func functionBody(root, file, name string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(file))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		return "", err
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name || function.Body == nil {
			continue
		}
		start := fset.Position(function.Body.Pos()).Offset
		end := fset.Position(function.Body.End()).Offset
		return string(data[start:end]), nil
	}
	return "", fmt.Errorf("%s missing function %s", file, name)
}

type functionCheck struct {
	file   string
	name   string
	before string
	after  string
}

func (check functionCheck) run(root string) error {
	path := filepath.Join(root, filepath.FromSlash(check.file))
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		return err
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != check.name || function.Body == nil {
			continue
		}
		start := fset.Position(function.Body.Pos()).Offset
		end := fset.Position(function.Body.End()).Offset
		body := string(data[start:end])
		beforeIndex := strings.Index(body, check.before)
		afterIndex := strings.Index(body, check.after)
		if beforeIndex < 0 {
			return fmt.Errorf("%s:%s missing guard %q", check.file, check.name, check.before)
		}
		if afterIndex < 0 {
			return fmt.Errorf("%s:%s missing protected sink %q", check.file, check.name, check.after)
		}
		if beforeIndex >= afterIndex {
			return fmt.Errorf("%s:%s guard %q does not precede %q", check.file, check.name, check.before, check.after)
		}
		return nil
	}
	return fmt.Errorf("%s missing function %s", check.file, check.name)
}
