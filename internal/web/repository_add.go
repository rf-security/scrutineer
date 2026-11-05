package web

import (
	"context"
	"fmt"
	"os"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// AddRepository adds the repository and queues the default triage pipeline
// the same way the add form does. It is used by `scrutineer audit`. isNew is
// false when the repository was already present, in which case no scan is
// queued.
func (s *Server) AddRepository(ctx context.Context, raw string) (db.Repository, bool, error) {
	input, err := ParseRepoInput(raw)
	if err != nil {
		return db.Repository{}, false, err
	}
	return s.createOrTriageRepo(ctx, input, "", true)
}

// repoAddResult is what one add did: the row, whether it was created, and
// the scan it queued (ScanID 0 when nothing was queued).
type repoAddResult struct {
	Repo      db.Repository
	Created   bool
	ScanID    uint
	ScanGroup string
}

// addRepositoryInput is createOrTriageRepo's body (moved here unchanged so
// the JSON add endpoints can report the queued scan). It creates the
// Repository row and its audit event, then enqueues the default skill when the
// row is new and triage is true; a bare re-add of an existing repo queues
// nothing, while a re-add naming a branch or sub-path still does.
func (s *Server) addRepositoryInput(ctx context.Context, input RepoInput, model string, triage bool) (repoAddResult, error) {
	if input.Local {
		path := strings.TrimPrefix(input.CloneURL, LocalScheme)
		info, err := os.Stat(path)
		if err != nil {
			return repoAddResult{}, fmt.Errorf("local path %s: %w", path, err)
		}
		if !info.IsDir() {
			return repoAddResult{}, fmt.Errorf("local path %s is not a directory", path)
		}
	}
	// Reject a traversal attempt in a submitted sub-path (repo#../x) before it
	// is stored on a Subproject or a scan, and normalise it so equivalent forms
	// dedupe.
	cleanedSub, err := worker.CleanSubPath(input.SubPath)
	if err != nil {
		return repoAddResult{}, err
	}
	input.SubPath = cleanedSub
	// Owner, FullName, and HTMLURL seed from ParseRepoInput so the orgs
	// view groups newly added repos and finding-location links work before
	// the metadata job has run; the metadata job later overwrites them
	// with the canonical forge values.
	repo := db.Repository{
		URL:     input.CloneURL,
		Name:    input.Name,
		Owner:   input.Owner,
		HTMLURL: DefaultHTMLURL(input.CloneURL),
	}
	if input.Owner != "" {
		repo.FullName = input.Owner + "/" + input.Name
	}
	isNew, err := s.createRepositoryWithAudit(ctx, &repo)
	res := repoAddResult{Repo: repo, Created: isNew}
	if err != nil {
		res.Created = false
		return res, err
	}
	// Eagerly warm the ecosyste.ms cache for a freshly added remote repo, in
	// parallel with the triage enqueue below. Local repos have no
	// upstream entry; the goroutine is best-effort and detached from ctx.
	if isNew && !repo.IsLocal() && s.prefetchEcosystems != nil {
		s.prefetchEcosystems(repo.ID)
	}
	// A repo#sub/dir (or /tree/<branch>/<path>) submission names a specific
	// sub-package. Record it as a first-class Subproject now so it is navigable
	// immediately, without waiting for the subprojects skill to rediscover it;
	// the skill's later upsert (keyed on repo+path) adopts and enriches this
	// row rather than duplicating it.
	if input.SubPath != "" {
		if err := db.EnsureSubproject(s.DB, repo.ID, input.SubPath); err != nil {
			s.Log.Warn("ensure submitted subproject", "repo", repo.ID, "path", input.SubPath, "err", err)
		}
	}
	if !triage {
		return res, nil
	}
	if !isNew && input.Branch == "" && input.SubPath == "" {
		res.Created = false
		return res, nil
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", defaultSkillName, true).First(&skill).Error; err != nil {
		s.Log.Warn("default skill not found, repo added with no scans", "skill", defaultSkillName)
		return res, nil
	}
	if repo.IsLocal() && skill.RequiresRemote {
		s.Log.Info("default skill requires remote, skipping for local repo", "skill", skill.Name, "repo", repo.URL)
		return res, nil
	}
	scanID, err := s.enqueueSkillWith(ctx, repo.ID, skill.ID, ScanOpts{
		Model:   model,
		SubPath: input.SubPath,
		Ref:     input.Branch,
	})
	if err != nil {
		return res, err
	}
	res.ScanID = scanID
	var sc db.Scan
	if s.DB.Select("id", "scan_group").First(&sc, scanID).Error == nil {
		res.ScanGroup = sc.ScanGroup
	}
	return res, nil
}
