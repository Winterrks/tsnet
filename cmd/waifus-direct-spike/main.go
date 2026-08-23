// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command waifus-direct-spike owns the public direct-only feasibility harness.
// The executable is intentionally inert: the reproducible lifecycle and
// packet assertions run under `go test`, where local STUN and cleanup can be
// bounded reliably without embedding production coordination behavior.
package main

import "fmt"

func main() {
	fmt.Println("waifus direct-only spike: run `go test -tags=waifus_direct_only ./cmd/waifus-direct-spike`")
}
