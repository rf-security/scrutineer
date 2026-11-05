package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

const scanConfigTab = "#rt14"

// repoScanConfigSave validates and persists the analyst-authored repository
// guidance. Empty input deliberately clears the configuration.
func (s *Server) repoScanConfigSave(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	config, _, err := repoconfig.Normalise(r.FormValue("scan_config"))
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("scan_config", config).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Scan config saved"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

func (s *Server) repoIgnoredPathAdd(w http.ResponseWriter, r *http.Request) {
	s.repoIgnoredPathEdit(w, r, true)
}

func (s *Server) repoIgnoredPathDelete(w http.ResponseWriter, r *http.Request) {
	s.repoIgnoredPathEdit(w, r, false)
}

// repoIgnoredPathEdit is the HTML add/remove form handler; the JSON twin in
// ui_repositories_write.go calls editIgnoredPath directly.
func (s *Server) repoIgnoredPathEdit(w http.ResponseWriter, r *http.Request, add bool) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	changed, err := s.editIgnoredPath(repo, r.FormValue("pattern"), add)
	var inputErr scanConfigInputError
	switch {
	case errors.As(err, &inputErr):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch {
	case add && !changed:
		setFlash(w, Flash{Category: "success", Title: "Ignored path already exists"})
	case add:
		setFlash(w, Flash{Category: "success", Title: "Ignored path added"})
	case !changed:
		setFlash(w, Flash{Category: "warning", Title: "Ignored path was not configured"})
	default:
		setFlash(w, Flash{Category: "success", Title: "Ignored path removed"})
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

// scanConfigInputError is a rejected scan config or ignored-path pattern: the
// operator's input (or the stored YAML it edits) is invalid, not the server.
type scanConfigInputError struct{ msg string }

func (e scanConfigInputError) Error() string { return e.msg }

// editIgnoredPath adds (add) or removes one ignored-path pattern on the
// repository's scan config. changed is false when the pattern was already
// present (add) or absent (remove); nothing is written then. Errors are a
// scanConfigInputError for bad input or stored YAML, anything else is a
// storage failure.
func (s *Server) editIgnoredPath(repo db.Repository, raw string, add bool) (bool, error) {
	cfg, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		return false, scanConfigInputError{"scan config is not valid YAML: " + err.Error()}
	}
	pattern, err := normaliseIgnoredPathPattern(raw)
	if err != nil {
		return false, err
	}
	before := len(cfg.Skip)
	if add {
		if slices.Contains(cfg.Skip, pattern) {
			return false, nil
		}
		cfg.Skip = append(cfg.Skip, pattern)
	} else {
		cfg.Skip = slices.DeleteFunc(cfg.Skip, func(skip string) bool {
			return skip == pattern
		})
		if len(cfg.Skip) == before {
			return false, nil
		}
	}
	config, err := repoconfig.NormaliseConfig(cfg)
	if err != nil {
		return false, scanConfigInputError{"scan config is not valid: " + err.Error()}
	}
	if err := s.saveScanConfig(repo.ID, config); err != nil {
		return false, err
	}
	return true, nil
}

func normaliseIgnoredPathPattern(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", scanConfigInputError{"ignored path pattern is required"}
	}
	pattern, err := repoconfig.NormaliseSkipPattern(raw)
	if err != nil {
		return "", scanConfigInputError{"ignored path pattern is not valid: " + err.Error()}
	}
	return pattern, nil
}

func (s *Server) repoScanConfigClear(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("scan_config", "").Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Scan config cleared"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

func repoIgnoredPaths(repo db.Repository) []string {
	cfg, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		return nil
	}
	return cfg.Skip
}

func (s *Server) saveScanConfig(repoID uint, config string) error {
	return s.DB.Model(&db.Repository{}).Where("id = ?", repoID).
		Update("scan_config", config).Error
}
