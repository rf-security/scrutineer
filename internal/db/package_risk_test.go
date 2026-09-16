package db

import (
	"reflect"
	"testing"
)

func TestNormalisePackageRiskFlags(t *testing.T) {
	tests := []struct {
		name        string
		ids         []string
		wantKept    []string
		wantDropped []string
	}{
		{
			name:     "canonical reordering",
			ids:      []string{"stale_release", "single_maintainer"},
			wantKept: []string{"single_maintainer", "stale_release"},
		},
		{
			name:     "dedup",
			ids:      []string{"native_extension", "native_extension"},
			wantKept: []string{"native_extension"},
		},
		{
			name:     "whitespace trimmed",
			ids:      []string{"  single_maintainer  ", " stale_release"},
			wantKept: []string{"single_maintainer", "stale_release"},
		},
		{
			name:     "empty strings skipped",
			ids:      []string{"", "   ", "single_maintainer"},
			wantKept: []string{"single_maintainer"},
		},
		{
			name:        "unknown ids dropped and deduped",
			ids:         []string{"bogus", "single_maintainer", "bogus", "also_bogus"},
			wantKept:    []string{"single_maintainer"},
			wantDropped: []string{"bogus", "also_bogus"},
		},
		{
			name: "nil for empty input",
			ids:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, dropped := NormalisePackageRiskFlags(tt.ids)
			if !reflect.DeepEqual(kept, tt.wantKept) {
				t.Errorf("kept = %#v, want %#v", kept, tt.wantKept)
			}
			if !reflect.DeepEqual(dropped, tt.wantDropped) {
				t.Errorf("dropped = %#v, want %#v", dropped, tt.wantDropped)
			}
		})
	}
}

func TestPackageRiskFlagLabel(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{id: "single_maintainer", want: "single maintainer"},
		{id: "no_security_policy", want: "no security policy"},
		{id: "native_extension", want: "ships native code"},
		{id: "stale_release", want: "no recent release"},
		{id: "maintainer_domain_expired", want: "maintainer domain expired"},
		{id: "unknown_id", want: "unknown_id"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := PackageRiskFlagLabel(tt.id); got != tt.want {
				t.Errorf("PackageRiskFlagLabel(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestPackageRiskFlags(t *testing.T) {
	tests := []struct {
		name   string
		joined string
		want   []string
	}{
		{
			name:   "split and trim",
			joined: "single_maintainer, stale_release,native_extension",
			want:   []string{"single_maintainer", "stale_release", "native_extension"},
		},
		{
			name:   "empty input",
			joined: "",
			want:   nil,
		},
		{
			name:   "all-blank input",
			joined: " , ,  ",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PackageRiskFlags(tt.joined)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PackageRiskFlags(%q) = %#v, want %#v", tt.joined, got, tt.want)
			}
		})
	}
}
