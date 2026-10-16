package worker

import "testing"

func TestMatchProfileNodeManifest(t *testing.T) {
	for _, tt := range []struct {
		name, report, want string
	}{
		{"workspace package", `{"manifests":[{"ecosystem":"npm","path":"package.json","kind":"manifest"}]}`, "node"},
		{"case insensitive ecosystem", `{"manifests":[{"ecosystem":"NPM","path":"package.json","kind":"manifest"}]}`, "node"},
		{"nested package", `{"manifests":[{"ecosystem":"npm","path":"docs/package.json","kind":"manifest"}]}`, ""},
		{"lockfile only", `{"manifests":[{"ecosystem":"npm","path":"package.json","kind":"lockfile"}]}`, ""},
		{"other ecosystem", `{"manifests":[{"ecosystem":"composer","path":"package.json","kind":"manifest"}]}`, ""},
		{"PHP priority", `{"package_managers":[{"name":"Composer"}],"manifests":[{"ecosystem":"npm","path":"package.json","kind":"manifest"}]}`, "php"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchProfile([]byte(tt.report)); got.Name != tt.want {
				t.Fatalf("profile = %q, want %q", got.Name, tt.want)
			}
		})
	}
}
