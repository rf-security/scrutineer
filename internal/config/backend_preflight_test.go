package config

import (
	"testing"
	"time"
)

func TestParseBackendPreflightTTL(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    time.Duration
		invalid bool
	}{
		{"", 0, false}, {"0", 0, false}, {"1h", time.Hour, false}, {"-1s", 0, true}, {"no", 0, true},
	} {
		got, err := ParseBackendPreflightTTL(tc.input)
		if got != tc.want || (err != nil) != tc.invalid {
			t.Errorf("%q: %s, %v", tc.input, got, err)
		}
	}
}
