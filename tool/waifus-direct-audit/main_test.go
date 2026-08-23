// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestAuditRepository(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range auditRepository(root) {
		t.Error(failure)
	}
}
