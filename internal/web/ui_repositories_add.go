package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"scrutineer/internal/db"
)

// Adding repositories over JSON (02 #48-#53). Every path goes through
// addRepositoryInput, so dedup and the default triage enqueue behave exactly
// like the HTML dialogs. created:false with no ref/sub-path enqueues nothing.

// uiRepoAddResult is the RepoCreateResult body.
func (s *Server) uiRepoAddResult(res repoAddResult) (map[string]any, error) {
	row, err := s.loadUIRepoRow(res.Repo.ID)
	if err != nil {
		return nil, err
	}
	ids := []uint{}
	var primary any
	if res.ScanID != 0 {
		ids = append(ids, res.ScanID)
		primary = res.ScanID
	}
	return map[string]any{
		uiKeyRepository: row, "created": res.Created, "scan_ids": ids, "scan_group": res.ScanGroup, uiEventScanIDKey: primary,
	}, nil
}

// addErrStatus maps an add failure: bad input (sub-path traversal, local path,
// ref) is 422, anything else 500.
func addErrStatus(err error) (int, string) {
	status, code := enqueueErrStatus(err)
	if status != http.StatusInternalServerError {
		return status, code
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "sub_path must not") || strings.HasPrefix(msg, "local path ") {
		return http.StatusUnprocessableEntity, uiCodeValidationFailed
	}
	return status, code
}

// ---------------------------------------------------------------- #49 single add

// uiRepoCreateBody is RepoCreate; triage defaults to true (parity).
type uiRepoCreateBody struct {
	URL    string `json:"url"`
	Ref    string `json:"ref"`
	Model  string `json:"model"`
	Triage *bool  `json:"triage"`
}

func triageOrDefault(v *bool) bool { return v == nil || *v }

func (s *Server) uiRepoCreate(w http.ResponseWriter, r *http.Request) {
	var body uiRepoCreateBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	input, err := ParseRepoInput(body.URL)
	if err != nil {
		writeUIFields(w, uiFieldErrors{uiKeyURL: err.Error()})
		return
	}
	// As repoCreate: the explicit branch wins over a /tree/<branch> suffix.
	if ref := strings.TrimSpace(body.Ref); ref != "" {
		input.Branch = ref
	}
	res, err := s.addRepositoryInput(r.Context(), input, body.Model, triageOrDefault(body.Triage))
	if err != nil {
		status, code := addErrStatus(err)
		writeUIError(w, status, code, err.Error(), nil)
		return
	}
	if res.Created {
		s.publishRepository(res.Repo.ID, uiChangeCreated)
	}
	out, err := s.uiRepoAddResult(res)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusCreated, out)
}

// ---------------------------------------------------------------- #48 branches

func (s *Server) uiRepoBranches(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get(uiKeyURL)
	if strings.TrimSpace(raw) == "" {
		uiBadParam(w, "url is required")
		return
	}
	input, err := ParseRepoInput(raw)
	if err != nil {
		writeUIFields(w, uiFieldErrors{uiKeyURL: err.Error()})
		return
	}
	branches := []string{}
	if !input.Local && s.listBranches != nil {
		ctx, cancel := context.WithTimeout(r.Context(), branchListTimeout)
		defer cancel()
		// Best-effort, as repoBranches: a timeout or unreachable remote is an
		// empty list, never an error.
		if got, err := s.listBranches(ctx, input.CloneURL); err == nil && got != nil {
			branches = got
		}
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"branches": branches})
}

// ---------------------------------------------------------------- #50 bulk

type uiRepoBulkBody struct {
	URLs   []string `json:"urls"`
	Text   string   `json:"text"`
	Model  string   `json:"model"`
	Triage *bool    `json:"triage"`
}

// lines is urls followed by text's lines.
func (b uiRepoBulkBody) lines() []string {
	out := append([]string{}, b.URLs...)
	if b.Text != "" {
		out = append(out, strings.Split(b.Text, "\n")...)
	}
	return out
}

func (s *Server) uiRepoBulkCreate(w http.ResponseWriter, r *http.Request) {
	var body uiRepoBulkBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	var added, queued, present int
	invalid := []map[string]any{}
	ids := []uint{}
	for i, line := range body.lines() {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		input, err := ParseRepoInput(line)
		if err == nil {
			var res repoAddResult
			res, err = s.addRepositoryInput(r.Context(), input, body.Model, triageOrDefault(body.Triage))
			if err == nil {
				// The same buckets as repoBulkCreate.
				switch {
				case res.Created:
					added++
					s.publishRepository(res.Repo.ID, uiChangeCreated)
				case input.SubPath != "" || input.Branch != "":
					queued++
				default:
					present++
				}
				ids = append(ids, res.Repo.ID)
				continue
			}
		}
		invalid = append(invalid, map[string]any{"line": i + 1, uiKeyURL: line, errorKey: err.Error()})
	}
	if added+queued+present == 0 && len(invalid) == 0 {
		writeUIFields(w, uiFieldErrors{"urls": "no URLs supplied"})
		return
	}
	rows, err := s.uiRepoRows(uniqueIDs(ids))
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"added": added, "queued": queued, "present": present, "invalid": invalid, "repositories": rows,
	})
}

// ---------------------------------------------------------------- #51 org import

type uiOrgImportBody struct {
	Org             string `json:"org"`
	IncludeForks    bool   `json:"include_forks"`
	IncludeArchived bool   `json:"include_archived"`
	Model           string `json:"model"`
	Triage          *bool  `json:"triage"`
}

// fetchOrgCandidates validates the org name and lists the import
// candidates, writing 422/502 on failure.
func (s *Server) fetchOrgCandidates(w http.ResponseWriter, r *http.Request) (uiOrgImportBody, []OrgRepo, int, bool) {
	var body uiOrgImportBody
	if !uiDecodeBody(w, r, &body) {
		return body, nil, 0, false
	}
	body.Org = strings.TrimPrefix(strings.TrimSpace(body.Org), "@")
	if body.Org == "" {
		writeUIFields(w, uiFieldErrors{"org": "enter a GitHub organization name"})
		return body, nil, 0, false
	}
	repos, err := s.fetchOrgRepos(r.Context(), body.Org)
	if err != nil {
		writeUIError(w, http.StatusBadGateway, uiCodeNetwork, err.Error(), nil)
		return body, nil, 0, false
	}
	candidates, filtered := filterOrgRepos(repos, body.IncludeForks, body.IncludeArchived)
	return body, candidates, filtered, true
}

func (s *Server) uiOrgImportPreview(w http.ResponseWriter, r *http.Request) {
	body, candidates, filtered, ok := s.fetchOrgCandidates(w, r)
	if !ok {
		return
	}
	repos := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		name := c.FullName
		if _, after, cut := strings.Cut(name, "/"); cut {
			name = after
		}
		repos = append(repos, map[string]any{
			uiKeyURL: c.CloneURL, uiKeyName: name, "full_name": c.FullName, "fork": c.Fork, "archived": c.Archived, "stars": c.Stars,
		})
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"org": body.Org, "total": len(candidates), "filtered": filtered, "repos": repos})
}

func (s *Server) uiOrgImport(w http.ResponseWriter, r *http.Request) {
	body, candidates, filtered, ok := s.fetchOrgCandidates(w, r)
	if !ok {
		return
	}
	var created, skipped, errored int
	ids := []uint{}
	errs := []map[string]string{}
	for _, c := range candidates {
		input, err := ParseRepoInput(c.CloneURL)
		if err == nil {
			var res repoAddResult
			res, err = s.addRepositoryInput(r.Context(), input, body.Model, triageOrDefault(body.Triage))
			if err == nil {
				if res.Created {
					created++
					s.publishRepository(res.Repo.ID, uiChangeCreated)
				} else {
					skipped++
				}
				ids = append(ids, res.Repo.ID)
				continue
			}
		}
		errored++
		errs = append(errs, map[string]string{"full_name": c.FullName, errorKey: err.Error()})
	}
	rows, err := s.uiRepoRows(ids)
	if err != nil {
		uiInternal(w, err)
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]any{
		"org": body.Org, "created": created, "skipped": skipped, "errored": errored, "filtered": filtered,
		"errors": errs, "repositories": rows,
	})
}

// ---------------------------------------------------------------- #52 investigations

func (s *Server) uiInvestigationCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL    string `json:"url"`
		Ref    string `json:"ref"`
		Report string `json:"report"`
	}
	if !uiDecodeBodyLimit(w, r, &body, importMaxBody) {
		return
	}
	scanID, repoID, status, err := s.startInvestigation(r.Context(), body.URL, body.Ref, body.Report)
	if err != nil {
		writeUIError(w, status, "", err.Error(), nil)
		return
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{uiEventScanIDKey: scanID, repositoryIDKey: repoID})
}

// ---------------------------------------------------------------- #53 dependency / dependent import

func (s *Server) uiDependencyImport(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var dep db.Dependency
	if err := s.DB.First(&dep, id).Error; err != nil {
		uiDBError(w, err, "dependency")
		return
	}
	// As depScan: no PURL keeps the 422; a PURL with enrichment off is 503.
	if dep.PURL != "" && !s.ecosystemsEnrichment {
		writeUIError(w, http.StatusServiceUnavailable, uiCodeUnavailable, "cannot resolve "+dep.Name+": "+ecosystemsDisabled, nil)
		return
	}
	repoURL := s.resolvePURL(r.Context(), dep.PURL)
	if repoURL == "" {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, "could not resolve repository URL for "+dep.Name, nil)
		return
	}
	s.uiImportRepoURL(w, r, repoURL)
}

func (s *Server) uiDependentImport(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var dep db.Dependent
	if err := s.DB.First(&dep, id).Error; err != nil {
		uiDBError(w, err, "dependent")
		return
	}
	if dep.RepositoryURL == "" {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, "no repository URL for this dependent", nil)
		return
	}
	s.uiImportRepoURL(w, r, dep.RepositoryURL)
}

// uiImportRepoURL is addRepoAndScan returning the ids: create (or find) the
// repo and triage it when new.
func (s *Server) uiImportRepoURL(w http.ResponseWriter, r *http.Request, repoURL string) {
	var body uiRepoModelBody
	if !uiDecodeBody(w, r, &body) {
		return
	}
	input, err := ParseRepoInput(repoURL)
	if err != nil {
		writeUIError(w, http.StatusUnprocessableEntity, uiCodeValidationFailed, err.Error(), nil)
		return
	}
	res, err := s.addRepositoryInput(r.Context(), input, body.Model, true)
	if err != nil {
		status, code := addErrStatus(err)
		writeUIError(w, status, code, fmt.Sprintf("import %s: %v", repoURL, err), nil)
		return
	}
	if res.Created {
		s.publishRepository(res.Repo.ID, uiChangeCreated)
	}
	var scanID any
	if res.ScanID != 0 {
		scanID = res.ScanID
	}
	writeUIJSON(w, http.StatusAccepted, map[string]any{repositoryIDKey: res.Repo.ID, uiEventScanIDKey: scanID, "created": res.Created})
}
