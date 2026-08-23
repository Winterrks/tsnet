// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !waifus_direct_only

package wgengine

import (
	"errors"
	"testing"

	"tailscale.com/types/logger"
	"tailscale.com/util/usermetric"
)

func TestDirectOnlyRequiresTaggedBuild(t *testing.T) {
	engine, err := NewUserspaceEngine(logger.Discard, Config{
		DirectOnly: true,
		Metrics:    new(usermetric.Registry),
	})
	if engine != nil {
		engine.Close()
		t.Fatal("NewUserspaceEngine returned an engine without the required build tag")
	}
	if !errors.Is(err, ErrDirectOnlyBuildRequired) {
		t.Fatalf("NewUserspaceEngine error = %v, want %v", err, ErrDirectOnlyBuildRequired)
	}
}
