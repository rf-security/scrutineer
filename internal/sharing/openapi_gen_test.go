package sharing

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// buildPortalSpec generates openapi.portal.yaml: the GET operations of
// openapi.yaml named by apiRoutes (re-keyed to their full /api/v1/ui path),
// merged with the hand-written openapi_auth.yaml, and the components both
// transitively $ref, pruned of everything else. It is test code because the
// spec is a build artefact checked by TestPortalOpenAPIGolden, not something
// the binary serves.
func buildPortalSpec(base, auth []byte) ([]byte, error) {
	broot, err := parseYAMLRoot(base)
	if err != nil {
		return nil, fmt.Errorf("openapi.yaml: %w", err)
	}
	aroot, err := parseYAMLRoot(auth)
	if err != nil {
		return nil, fmt.Errorf("openapi_auth.yaml: %w", err)
	}
	bpaths, bcomp := mapGet(broot, "paths"), mapGet(broot, "components")
	apaths, acomp := mapGet(aroot, "paths"), mapGet(aroot, "components")
	if bpaths == nil || bcomp == nil || apaths == nil || acomp == nil {
		return nil, fmt.Errorf("both documents need paths and components")
	}

	paths := newMap()
	for _, rt := range apiRoutes {
		method, full, ok := strings.Cut(rt.pattern, " ")
		if !ok || method != "GET" || !strings.HasPrefix(full, "/api/") {
			return nil, fmt.Errorf("allow-listed route %q is not a GET under /api/", rt.pattern)
		}
		item := mapGet(bpaths, strings.TrimPrefix(full, "/api"))
		if item == nil {
			return nil, fmt.Errorf("allow-listed route %q is not in openapi.yaml", rt.pattern)
		}
		op := mapGet(item, "get")
		if op == nil {
			return nil, fmt.Errorf("allow-listed route %q has no get operation in openapi.yaml", rt.pattern)
		}
		out := newMap()
		if params := mapGet(item, "parameters"); params != nil {
			mapSet(out, "parameters", deepCopy(params))
		}
		mapSet(out, "get", portalOperation(op))
		mapSet(paths, full, out)
	}
	for i := 0; i+1 < len(apaths.Content); i += 2 {
		if mapGet(paths, apaths.Content[i].Value) != nil {
			return nil, fmt.Errorf("openapi_auth.yaml path %q duplicates a forwarded route", apaths.Content[i].Value)
		}
		mapSet(paths, apaths.Content[i].Value, deepCopy(apaths.Content[i+1]))
	}

	// Transitive $ref closure over the output paths and every hand-written
	// component. openapi_auth.yaml components shadow openapi.yaml ones.
	need := map[string]map[string]bool{}
	resolve := func(sec, name string) *yaml.Node {
		if n := mapGet(mapGet(acomp, sec), name); n != nil {
			return n
		}
		return mapGet(mapGet(bcomp, sec), name)
	}
	var queue []*yaml.Node
	var walkErr error
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value != "$ref" {
					continue
				}
				ref := n.Content[i+1].Value
				parts := strings.Split(strings.TrimPrefix(ref, "#/components/"), "/")
				if !strings.HasPrefix(ref, "#/components/") || len(parts) != 2 {
					walkErr = fmt.Errorf("unsupported $ref %q", ref)
					return
				}
				if need[parts[0]] == nil {
					need[parts[0]] = map[string]bool{}
				}
				if need[parts[0]][parts[1]] {
					continue
				}
				target := resolve(parts[0], parts[1])
				if target == nil {
					walkErr = fmt.Errorf("dangling $ref %q", ref)
					return
				}
				need[parts[0]][parts[1]] = true
				queue = append(queue, target)
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	queue = append(queue, paths)
	for i := 0; i+1 < len(acomp.Content); i += 2 {
		sec := acomp.Content[i].Value
		for j := 0; j+1 < len(acomp.Content[i+1].Content); j += 2 {
			if need[sec] == nil {
				need[sec] = map[string]bool{}
			}
			need[sec][acomp.Content[i+1].Content[j].Value] = true
			queue = append(queue, acomp.Content[i+1].Content[j+1])
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		walk(n)
		if walkErr != nil {
			return nil, walkErr
		}
	}

	// Sections and names keep openapi.yaml's order; hand-written additions
	// follow in their own order.
	comps := newMap()
	var sections []string
	for _, root := range []*yaml.Node{bcomp, acomp} {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if sec := root.Content[i].Value; need[sec] != nil && !contains(sections, sec) {
				sections = append(sections, sec)
			}
		}
	}
	for _, sec := range sections {
		out := newMap()
		for _, root := range []*yaml.Node{mapGet(bcomp, sec), mapGet(acomp, sec)} {
			if root == nil {
				continue
			}
			for i := 0; i+1 < len(root.Content); i += 2 {
				name := root.Content[i].Value
				if need[sec][name] && mapGet(out, name) == nil {
					mapSet(out, name, deepCopy(resolve(sec, name)))
				}
			}
		}
		mapSet(comps, sec, out)
	}

	ainfo := mapGet(aroot, "info")
	info := newMap()
	mapSet(info, "title", deepCopy(mapGet(ainfo, "title")))
	mapSet(info, "version", deepCopy(mapGet(mapGet(broot, "info"), "version")))
	mapSet(info, "description", deepCopy(mapGet(ainfo, "description")))

	server := newMap()
	mapSet(server, "url", scalar("/"))
	mapSet(server, "description", scalar("The portal origin (paths are absolute)"))
	sec := newMap()
	mapSet(sec, "portalSession", &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle})

	doc := newMap()
	mapSet(doc, "openapi", deepCopy(mapGet(broot, "openapi")))
	mapSet(doc, "info", info)
	mapSet(doc, "servers", seq(server))
	mapSet(doc, "security", seq(sec))
	mapSet(doc, "paths", paths)
	mapSet(doc, "components", comps)
	stripComments(doc)

	var buf bytes.Buffer
	buf.WriteString("# GENERATED from openapi.yaml and internal/sharing/openapi_auth.yaml. Do not edit.\n" +
		"# Regenerate: go test ./internal/sharing -run TestPortalOpenAPIGolden -update\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// portalOperation adapts a forwarded operation: the portal session replaces
// the operator security, 2xx answers document X-Portal-Scope, and every
// operation can answer 401 and 503.
func portalOperation(op *yaml.Node) *yaml.Node {
	out := deepCopy(op)
	mapDelete(out, "security")
	responses := mapGet(out, "responses")
	if responses == nil {
		responses = newMap()
		mapSet(out, "responses", responses)
	}
	for i := 0; i+1 < len(responses.Content); i += 2 {
		resp := responses.Content[i+1]
		if !strings.HasPrefix(responses.Content[i].Value, "2") || mapGet(resp, "$ref") != nil {
			continue
		}
		headers := mapGet(resp, "headers")
		if headers == nil {
			headers = newMap()
			mapSet(resp, "headers", headers)
		}
		mapSet(headers, "X-Portal-Scope", refNode("#/components/headers/PortalScope"))
	}
	for code, ref := range map[string]string{"401": "UIUnauthorized", "503": "UIUnavailable"} {
		if mapGet(responses, code) == nil {
			mapSet(responses, code, refNode("#/components/responses/"+ref))
		}
	}
	sortResponses(responses)
	return out
}

// sortResponses orders response codes so the map-ordered additions above are
// deterministic.
func sortResponses(m *yaml.Node) {
	type kv struct{ k, v *yaml.Node }
	var pairs []kv
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, kv{m.Content[i], m.Content[i+1]})
	}
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j].k.Value < pairs[j-1].k.Value; j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
	m.Content = m.Content[:0]
	for _, p := range pairs {
		m.Content = append(m.Content, p.k, p.v)
	}
}

func parseYAMLRoot(b []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a YAML mapping document")
	}
	return doc.Content[0], nil
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, scalar(key), v)
}

func mapDelete(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func newMap() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

// scalar is a string node; numeric-looking strings (response codes) are
// single-quoted to match openapi.yaml's style.
func scalar(v string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
	if _, err := strconv.Atoi(v); err == nil {
		n.Style = yaml.SingleQuotedStyle
	}
	return n
}

func seq(items ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items}
}

func refNode(ref string) *yaml.Node {
	n := newMap()
	mapSet(n, "$ref", scalar(ref))
	return n
}

func deepCopy(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, child := range n.Content {
		c.Content[i] = deepCopy(child)
	}
	return &c
}

func stripComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		stripComments(c)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
