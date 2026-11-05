package web

import (
	"regexp"
	"strconv"
	"strings"
)

// LocationRef parsing for the /api/v1/ui finding projections.
//
// The HTML UI links a location with splitLocation, whose regexp is anchored
// at the end: "src/lib.rs:12-34" links, but a model-written prose location
// such as "src/lib.rs:214-296 (insert); manifests in src/lib.rs:444-475"
// falls through and is linked as one bogus path. The JSON projection keeps
// splitLocation for every location it accepts and, only when it fails, picks
// the "path:N[-M]" references out of the prose.

// locTokenRE finds "path:N" / "path:N-M" references inside free text. The
// path stops at whitespace and at the punctuation prose wraps it in; a
// trailing ":col" (as in SARIF "file.js:42:7") is ignored like locRE does.
var locTokenRE = regexp.MustCompile("([^\\s:;,()\\[\\]{}<>\"'`]+):(\\d+)(?:-(\\d+))?")

// uiLocationRefs parses one stored location into LocationRefs: exactly one
// for a location splitLocation understands (or for prose with no
// recognisable file reference), one per distinct file reference otherwise.
func uiLocationRefs(location, commit string) []map[string]any {
	location = strings.TrimSpace(location)
	if location == "" {
		return nil
	}
	// A prose location that happens to end in "path:N" passes locRE with the
	// rest of the prose, including earlier references, in the path.
	strictPath, strictLines := splitLocation(location)
	if strictLines != "" && !locTokenRE.MatchString(strictPath) {
		return []map[string]any{newLocationRef(strictPath, strictLines, commit)}
	}
	var refs []map[string]any
	seen := map[string]bool{}
	for _, m := range locTokenRE.FindAllStringSubmatch(location, -1) {
		path := strings.TrimPrefix(m[1], "./")
		if !looksLikeFilePath(path) {
			continue
		}
		lines := m[2]
		if m[3] != "" {
			lines += "-" + m[3]
		}
		if key := path + ":" + lines; !seen[key] {
			seen[key] = true
			refs = append(refs, newLocationRef(path, lines, commit))
		}
	}
	if len(refs) == 0 {
		return []map[string]any{newLocationRef(strictPath, strictLines, commit)}
	}
	return refs
}

// looksLikeFilePath keeps "src/lib.rs" and "main.go" but drops scheme-less
// host:port pairs and bare words ("line:12") that are not file references.
func looksLikeFilePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "//") {
		return false
	}
	return strings.Contains(p, "/") || strings.Contains(p, ".")
}

// newLocationRef is one LocationRef; lines is "", "N" or "N-M".
func newLocationRef(path, lines, commit string) map[string]any {
	ref := map[string]any{"path": path, "line_start": 0, "line_end": nil, uiKeyCommit: commit}
	if lines == "" {
		return ref
	}
	a, b, ranged := strings.Cut(lines, "-")
	if n, err := strconv.Atoi(a); err == nil {
		ref["line_start"] = n
	}
	if ranged {
		if n, err := strconv.Atoi(b); err == nil {
			ref["line_end"] = n
		}
	}
	return ref
}

// uiLocationRef is FindingRow.location_ref: the first reference in location,
// or nil when it is empty.
func uiLocationRef(location, commit string) map[string]any {
	if refs := uiLocationRefs(location, commit); len(refs) > 0 {
		return refs[0]
	}
	return nil
}

// uiFindingLocations is FindingRow.locations: locations[0] is location_ref
// and the rest are the extra links. Several grouped positions
// (Finding.Locations) map one to one, as on the HTML page; a lone location
// with several file references in its prose yields one entry per reference.
func uiFindingLocations(location string, grouped []string, commit string) []map[string]any {
	locs := make([]map[string]any, 0, len(grouped))
	switch len(grouped) {
	case 0:
		return append(locs, uiLocationRefs(location, commit)...)
	case 1:
		return append(locs, uiLocationRefs(grouped[0], commit)...)
	}
	for _, l := range grouped {
		if ref := uiLocationRef(l, commit); ref != nil {
			locs = append(locs, ref)
		}
	}
	return locs
}
