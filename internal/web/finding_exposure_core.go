package web

import (
	"context"
	"errors"

	"scrutineer/internal/db"
)

// The exposure fan-out shared by the finding page (findingExposureRun) and
// POST /api/v1/ui/findings/{id}/actions/exposure.

var (
	// errExposureUnsupported is a finding whose producer cannot be traced into
	// dependents (zizmor workflow findings).
	errExposureUnsupported = errors.New("dependent exposure is not supported for this finding")
	// errExposureSkillMissing is a missing exposure skill.
	errExposureSkillMissing = errors.New("exposure skill is not installed")
	// errExposureNoDependents is a repository without recorded dependents.
	errExposureNoDependents = errors.New("no dependents recorded for this repository")
)

// enqueueExposure queues one exposure scan per top-N dependent of f's
// repository. Dependents without a repository URL are recorded as
// under_investigation and counted as skipped. Errors: errFindingScanMissing,
// errExposureUnsupported, errExposureSkillMissing, errExposureNoDependents;
// per-dependent enqueue failures are counted, not returned.
func (s *Server) enqueueExposure(ctx context.Context, f db.Finding, model string) (enqueueBatch, error) {
	var res enqueueBatch
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
		return res, errFindingScanMissing
	}
	if !findingSupportsExposure(scan) {
		return res, errExposureUnsupported
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", exposureSkillName, true).First(&skill).Error; err != nil {
		return res, errExposureSkillMissing
	}
	var deps []db.Dependent
	s.DB.Where("repository_id = ?", scan.RepositoryID).
		Order("dependent_repos desc, downloads desc").
		Limit(exposureTopN).
		Find(&deps)
	if len(deps) == 0 {
		return res, errExposureNoDependents
	}
	res.ScanIDs = []uint{}
	for i := range deps {
		dep := deps[i]
		if dep.RepositoryURL == "" {
			if err := s.recordSkippedExposure(f.ID, dep.ID); err != nil {
				res.Errored++
				continue
			}
			res.Skipped++
			continue
		}
		scanID, err := s.enqueueSkillWith(ctx, scan.RepositoryID, skill.ID, ScanOpts{
			Model:       model,
			FindingID:   &f.ID,
			DependentID: &dep.ID,
		})
		if err != nil {
			res.Errored++
			continue
		}
		res.ScanIDs = append(res.ScanIDs, scanID)
		res.Queued++
	}
	return res, nil
}
