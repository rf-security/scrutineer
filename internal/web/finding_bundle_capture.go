package web

import (
	"encoding/json"
	"errors"
	"fmt"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

// errCapturedPoC marks a stored capture that no longer decodes, so the bundle
// can fall back to the validation text instead of failing.
var errCapturedPoC = errors.New("read captured PoC")

func (s *Server) findingPoCEntries(finding *db.Finding) ([]bundleEntry, bool, error) {
	row, err := db.LoadFindingPoC(s.DB, finding.ID)
	if err != nil {
		return nil, false, err
	}
	if row == nil {
		return nil, false, nil
	}
	files, err := poc.Decode(row.Files)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", errCapturedPoC, err)
	}
	var entries []bundleEntry
	for _, file := range files {
		var mode int64
		if file.Executable {
			mode = runShMode
		}
		entries = append(entries, bundleEntry{Name: "poc/" + file.Path, Data: file.Data, Mode: mode})
	}
	manifest, err := json.MarshalIndent(row.Manifest(files), "", "  ")
	if err != nil {
		return nil, true, err
	}
	entries = append(entries, bundleEntry{Name: "poc-manifest.json", Data: manifest})
	return entries, true, nil
}
