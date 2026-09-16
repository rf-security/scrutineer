package web

import (
	"fmt"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type remediationAttemptView struct {
	db.RemediationAttempt
	Validation *db.RemediationValidation
	Status     string
}

func loadRemediationAttemptViews(gdb *gorm.DB, findingID uint) ([]remediationAttemptView, error) {
	var attempts []db.RemediationAttempt
	if err := gdb.Where("finding_id = ?", findingID).Order("attempt desc").Find(&attempts).Error; err != nil {
		return nil, fmt.Errorf("load remediation attempts: %w", err)
	}
	if len(attempts) == 0 {
		return nil, nil
	}

	ids := make([]uint, len(attempts))
	for i := range attempts {
		ids[i] = attempts[i].ID
	}
	var validations []db.RemediationValidation
	if err := gdb.Where("remediation_attempt_id IN ?", ids).
		Order("id desc").Find(&validations).Error; err != nil {
		return nil, fmt.Errorf("load remediation validations: %w", err)
	}
	latest := make(map[uint]*db.RemediationValidation, len(validations))
	for i := range validations {
		selected := latest[validations[i].RemediationAttemptID]
		if selected == nil ||
			(selected.RootCauseStatus != db.ReattackBypassedPatch &&
				validations[i].RootCauseStatus == db.ReattackBypassedPatch) {
			latest[validations[i].RemediationAttemptID] = &validations[i]
		}
	}

	views := make([]remediationAttemptView, len(attempts))
	for i := range attempts {
		validation := latest[attempts[i].ID]
		views[i] = remediationAttemptView{
			RemediationAttempt: attempts[i],
			Validation:         validation,
			Status:             db.RemediationPatchStatus(validation),
		}
	}
	return views, nil
}

func remediationAttemptResponse(attempt *db.RemediationAttempt, validation *db.RemediationValidation) map[string]any {
	result := map[string]any{
		"id":            attempt.ID,
		"attempt":       attempt.Attempt,
		"patch_scan_id": attempt.PatchScanID,
		"base_commit":   attempt.BaseCommit,
		"status":        db.RemediationPatchStatus(validation),
		"created_at":    attempt.CreatedAt,
	}
	if validation != nil {
		result["validation"] = map[string]any{
			"scan_id":               validation.ScanID,
			"outcome":               validation.RootCauseStatus,
			"valid_variants":        validation.ValidVariants,
			"benign_control_passed": validation.BenignControlPassed,
			"bypass_input":          validation.BypassInput,
			"created_at":            validation.CreatedAt,
		}
	}
	return result
}
