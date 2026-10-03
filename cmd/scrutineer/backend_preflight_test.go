package main

import (
	"testing"
	"time"

	"scrutineer/internal/config"
)

func TestBackendPreflightConfig(t *testing.T) {
	for _, tc := range []struct {
		ttl               time.Duration
		invalid, disabled bool
	}{
		{0, false, true}, {time.Hour, false, false}, {-time.Second, true, false},
	} {
		cache, err := configuredBackendPreflight(tc.ttl)
		if (err != nil) != tc.invalid || (!tc.invalid && (cache == nil) != tc.disabled) {
			t.Fatalf("ttl=%s cache=%v err=%v", tc.ttl, cache, err)
		}
	}
	for _, overridden := range []bool{false, true} {
		f := &flags{set: map[string]bool{"backend-preflight-ttl": overridden}}
		f.merge(&config.Config{BackendPreflightTTL: "1h"})
		want := time.Hour
		if overridden {
			want = 0
		}
		if f.backendPreflightTTL != want {
			t.Fatalf("override=%v got=%s", overridden, f.backendPreflightTTL)
		}
	}
}
