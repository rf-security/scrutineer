package web

import (
	"context"
	"errors"
	"fmt"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// The fix-validation enqueue shared by POST /repositories/{id}/validate-fix
// and POST /api/v1/ui/findings/{id}/actions/validate-fix.

// validateFixInputError is a request the pipeline refuses before enqueuing
// anything. Field names the offending input ("ref" or "finding_ids").
type validateFixInputError struct {
	Field string
	Msg   string
}

func (e validateFixInputError) Error() string { return e.Msg }

// errValidateFixBaselineMissing is a baseline scan row that is gone.
var errValidateFixBaselineMissing = errors.New("baseline scan not found")

// validateFixResult is the anchor re-scan plus the verify scans queued.
type validateFixResult struct {
	AnchorID      uint
	VerifyScanIDs []uint
}

// checkValidateFixRef validates the candidate fix ref.
func checkValidateFixRef(ref string) error {
	if ref == "" {
		return validateFixInputError{Field: "ref", Msg: "a fix ref is required"}
	}
	if err := worker.ValidateGitRef(ref); err != nil {
		return validateFixInputError{Field: "ref", Msg: fmt.Sprintf("invalid fix ref: %v", err)}
	}
	return nil
}

// enqueueValidateFix runs the fix-validation pipeline (see validateFix) for
// findingIDs on repoID against ref. Errors: validateFixInputError,
// errValidateFixBaselineMissing, a lookup error, or the anchor enqueue error.
func (s *Server) enqueueValidateFix(ctx context.Context, repoID uint, ref string, findingIDs []uint, model string) (validateFixResult, error) {
	var res validateFixResult
	if err := checkValidateFixRef(ref); err != nil {
		return res, err
	}
	if len(findingIDs) == 0 {
		return res, validateFixInputError{Field: "finding_ids", Msg: "at least one finding id is required"}
	}
	var findings []db.Finding
	if err := s.DB.Where("id IN ? AND repository_id = ?", findingIDs, repoID).Find(&findings).Error; err != nil {
		return res, err
	}
	if len(findings) != len(findingIDs) {
		return res, validateFixInputError{Field: "finding_ids", Msg: "some findings were not found on this repository"}
	}
	baselineScanID := findings[0].ScanID
	for _, f := range findings {
		if f.ScanID != baselineScanID {
			return res, validateFixInputError{Field: "finding_ids", Msg: "all findings must come from the same baseline scan"}
		}
	}

	var baseline db.Scan
	if err := s.DB.First(&baseline, baselineScanID).Error; err != nil {
		return res, errValidateFixBaselineMissing
	}
	if baseline.SkillID == nil {
		return res, validateFixInputError{Field: "finding_ids", Msg: "baseline scan has no skill to re-run against the fix ref"}
	}

	res.VerifyScanIDs = s.enqueueValidateFixVerify(ctx, repoID, findings, ref, model)

	anchorID, err := s.enqueueSkillWith(ctx, repoID, *baseline.SkillID, ScanOpts{
		Model:          model,
		Ref:            ref,
		SubPath:        baseline.SubPath,
		ScopeMode:      baseline.ScopeMode, // match the baseline's scope so the fix comparison is apples-to-apples
		BaselineScanID: &baselineScanID,
	})
	if err != nil {
		return res, err
	}
	res.AnchorID = anchorID
	return res, nil
}
