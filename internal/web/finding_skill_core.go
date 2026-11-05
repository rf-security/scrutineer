package web

import (
	"context"
	"errors"

	"scrutineer/internal/db"
)

// The finding skill launch shared by the finding page buttons
// (runFindingSkill) and POST /api/v1/ui/findings/{id}/actions/{action}.

// errFindingScanMissing is a finding whose producing scan row is gone.
var errFindingScanMissing = errors.New("scan for finding not found")

// findingSkillMissingError is an action whose skill is not installed.
type findingSkillMissingError struct{ Skill string }

func (e findingSkillMissingError) Error() string { return e.Skill + " skill is not installed" }

// findingSkillPreconditionError is a ScanOpts precondition failure (no gated
// patch to re-attack, a patch without a base commit). Its message is the cause.
type findingSkillPreconditionError struct{ Err error }

func (e findingSkillPreconditionError) Error() string { return e.Err.Error() }

func (e findingSkillPreconditionError) Unwrap() error { return e.Err }

// findingSkillLaunch is one requested launch.
type findingSkillLaunch struct {
	Skill string
	Model string
	// Feedback is the normalised verify feedback; ignored for other skills.
	Feedback string
	// SkipOpen makes the launch idempotent: an open scan of the same skill
	// (and remediation attempt) is returned instead of a new one.
	SkipOpen bool
}

// findingSkillResult is the scan a launch queued, or the open one it found.
type findingSkillResult struct {
	ScanID   uint
	Existing bool
}

// enqueueFindingSkillAction queues skill l.Skill scoped to f. Errors:
// errFindingScanMissing, findingSkillMissingError,
// findingSkillPreconditionError, ErrFederationClaimPending,
// db.ErrFindingNonViable, or an enqueue error.
func (s *Server) enqueueFindingSkillAction(ctx context.Context, f db.Finding, l findingSkillLaunch) (findingSkillResult, error) {
	if l.SkipOpen {
		// Keep the open-scan check and enqueue atomic with other finding launches.
		s.agentEnqueueMu.Lock()
		defer s.agentEnqueueMu.Unlock()
	}
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
		return findingSkillResult{}, errFindingScanMissing
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", l.Skill, true).First(&skill).Error; err != nil {
		return findingSkillResult{}, findingSkillMissingError{Skill: l.Skill}
	}
	opts, err := s.findingSkillScanOpts(f.ID, l.Skill, l.Model)
	if err != nil {
		return findingSkillResult{}, findingSkillPreconditionError{Err: err}
	}
	if l.SkipOpen {
		if openScan, ok := s.openFindingSkillScanForAttempt(f.ID, l.Skill, opts.RemediationAttemptID); ok {
			return findingSkillResult{ScanID: openScan.ID, Existing: true}, nil
		}
	}
	opts.FindingID = new(f.ID)
	opts.AuditDisclosure = externalReportingSkill(l.Skill)
	if l.Skill == verifySkillName {
		opts.VerificationFeedback = l.Feedback
	}
	scanID, err := s.enqueueSkillWith(ctx, scan.RepositoryID, skill.ID, opts)
	if err != nil {
		return findingSkillResult{}, err
	}
	return findingSkillResult{ScanID: scanID}, nil
}
