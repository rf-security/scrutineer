package worker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	ecosystems "github.com/ecosyste-ms/ecosystems-go"
)

func TestResolvePURLRepositoryURLsBulk(t *testing.T) {
	var batches [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/packages/bulk_lookup" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			PURLs []string `json:"purls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		batches = append(batches, body.PURLs)
		w.Header().Set("Content-Type", "application/json")
		response := make([]map[string]string, 0, len(body.PURLs))
		for _, p := range body.PURLs {
			response = append(response, map[string]string{"purl": p, "repository_url": "https://github.com/example/library"})
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	client, err := ecosystems.NewClient("test", ecosystems.WithPackagesServer(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	var input []string
	for i := range 101 {
		input = append(input, fmt.Sprintf("pkg:npm/library-%03d@1.0.0", i))
	}
	input = append(input, input[0], "pkg:npm/library-000@2.0.0", "not-a-purl")
	resolved, err := resolvePURLRepositoryURLs(t.Context(), client, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != 100 || len(batches[1]) != 1 {
		t.Fatalf("batches = %v", batches)
	}
	if !slices.Contains(batches[0], "pkg:npm/library-000") {
		t.Fatal("lookup did not use package identity")
	}
	if len(resolved) != 102 || resolved[input[0]] == "" || resolved["pkg:npm/library-000@2.0.0"] == "" {
		t.Fatalf("versioned results missing: %v", resolved)
	}
	if resolved["not-a-purl"] != "" {
		t.Fatal("invalid PURL resolved")
	}
}
