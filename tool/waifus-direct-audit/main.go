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
			file:   "wgengine/magicsock/magicsock.go",
			name:   "NewConn",
			before: "opts.DirectOnly && !directOnlyBuild",
			after:  "newConn",
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
			before: "DirectOnly:    s.waifusControl != nil",
			after:  "Tun:           s.Tun",
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
	}
	if constructorSites != 1 {
		failures = append(failures, fmt.Errorf("DERP client constructor sites = %d, want exactly 1 guarded site", constructorSites))
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
