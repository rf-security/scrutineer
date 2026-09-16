package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const (
	patchSkillName            = "patch"
	reattackSkillName         = "reattack"
	remediationContextFile    = "remediation.json"
	priorBypassesFile         = "prior-bypasses.json"
	remediationPatchFile      = "patch.diff"
	maxStagedPriorBypasses    = 20
	maxStagedBypassInputBytes = 16 << 10
	minReattackVariants       = 3
)

type priorBypass struct {
	Attempt int    `json:"attempt"`
	Input   string `json:"input"`
}

type priorBypassEnvelope struct {
	Bypasses  []priorBypass `json:"bypasses"`
	Truncated bool          `json:"truncated"`
}

type remediationContext struct {
	AttemptID         uint   `json:"attempt_id"`
	Attempt           int    `json:"attempt"`
	PatchScanID       uint   `json:"patch_scan_id"`
	BaseCommit        string `json:"base_commit"`
	PatchFile         string `json:"patch_file"`
	PriorBypassesFile string `json:"prior_bypasses_file"`
}

type reattackReport struct {
	Outcome       string                `json:"outcome"`
	Variants      []reattackVariant     `json:"variants"`
	BenignControl reattackBenignControl `json:"benign_control"`
	Notes         string                `json:"notes"`
}

type reattackVariant struct {
	Name         string `json:"name"`
	Input        string `json:"input"`
	Origin       string `json:"origin"`
	Valid        bool   `json:"valid"`
	Outcome      string `json:"outcome"`
	SameBugClass bool   `json:"same_bug_class"`
	SameSink     bool   `json:"same_sink"`
	FailureClass string `json:"failure_class"`
	Sink         string `json:"sink"`
	Evidence     string `json:"evidence"`
}

type reattackBenignControl struct {
	Input       string `json:"input"`
	ReachedSink bool   `json:"reached_sink"`
	Crashed     bool   `json:"crashed"`
	Evidence    string `json:"evidence"`
}

func (w *Worker) prepareRemediationWorkspace(workRoot string, scan *db.Scan, skill *db.Skill) error {
	if scan.FindingID == nil || (skill.Name != patchSkillName && skill.Name != reattackSkillName) {
		return nil
	}
	bypasses, err := w.priorBypasses(*scan.FindingID)
	if err != nil {
		return err
	}
	if err := writeRemediationJSON(filepath.Join(workRoot, priorBypassesFile), bypasses); err != nil {
		return fmt.Errorf("write prior bypasses: %w", err)
	}
	if skill.Name == patchSkillName {
		return nil
	}
	if scan.RemediationAttemptID == nil {
		return fmt.Errorf("reattack scan has no remediation_attempt_id")
	}

	var attempt db.RemediationAttempt
	if err := w.DB.First(&attempt, *scan.RemediationAttemptID).Error; err != nil {
		return fmt.Errorf("load remediation attempt %d: %w", *scan.RemediationAttemptID, err)
	}
	if attempt.FindingID != *scan.FindingID {
		return fmt.Errorf("remediation attempt %d belongs to finding %d, not %d",
			attempt.ID, attempt.FindingID, *scan.FindingID)
	}
	if scan.Ref != attempt.BaseCommit {
		return fmt.Errorf("reattack ref %q does not match remediation attempt base %q", scan.Ref, attempt.BaseCommit)
	}
	if err := os.WriteFile(filepath.Join(workRoot, remediationPatchFile), []byte(attempt.Patch), filePerm); err != nil {
		return fmt.Errorf("write remediation patch: %w", err)
	}
	if err := applyRemediationPatch(filepath.Join(workRoot, "src"), attempt.Patch); err != nil {
		return err
	}
	ctx := remediationContext{
		AttemptID:         attempt.ID,
		Attempt:           attempt.Attempt,
		PatchScanID:       attempt.PatchScanID,
		BaseCommit:        attempt.BaseCommit,
		PatchFile:         remediationPatchFile,
		PriorBypassesFile: priorBypassesFile,
	}
	if err := writeRemediationJSON(filepath.Join(workRoot, remediationContextFile), ctx); err != nil {
		return fmt.Errorf("write remediation context: %w", err)
	}
	return nil
}

func (w *Worker) priorBypasses(findingID uint) (priorBypassEnvelope, error) {
	type row struct {
		Attempt     int
		BypassInput string
	}
	var rows []row
	if err := w.DB.Table("remediation_validations").
		Select("remediation_attempts.attempt, remediation_validations.bypass_input").
		Joins("JOIN remediation_attempts ON remediation_attempts.id = remediation_validations.remediation_attempt_id").
		Where("remediation_validations.finding_id = ? AND remediation_validations.root_cause_status = ? AND remediation_validations.bypass_input <> ''",
			findingID, db.ReattackBypassedPatch).
		Order("remediation_attempts.attempt DESC, remediation_validations.id DESC").
		Find(&rows).Error; err != nil {
		return priorBypassEnvelope{}, fmt.Errorf("load prior remediation bypasses: %w", err)
	}

	out := priorBypassEnvelope{Bypasses: make([]priorBypass, 0, min(len(rows), maxStagedPriorBypasses))}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		input := boundedBypassInput(row.BypassInput)
		if input == "" || seen[input] {
			continue
		}
		seen[input] = true
		if len(out.Bypasses) == maxStagedPriorBypasses {
			out.Truncated = true
			break
		}
		out.Bypasses = append(out.Bypasses, priorBypass{Attempt: row.Attempt, Input: input})
	}
	return out, nil
}

func boundedBypassInput(input string) string {
	input = strings.TrimSpace(input)
	if len(input) <= maxStagedBypassInputBytes {
		return input
	}
	input = input[:maxStagedBypassInputBytes]
	for !utf8.ValidString(input) {
		input = input[:len(input)-1]
	}
	return input
}

func writeRemediationJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, filePerm)
}

func applyRemediationPatch(srcDir, patch string) error {
	cmd := exec.Command("git", "-C", srcDir, "apply", "-")
	cmd.Stdin = strings.NewReader(patch)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apply remediation patch: %w: %s", err, firstLine(output.String()))
	}
	return nil
}

func (w *Worker) parseReattackOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("reattack scan has no finding_id")
	}
	if scan.RemediationAttemptID == nil {
		return fmt.Errorf("reattack scan has no remediation_attempt_id")
	}
	parsed, validVariants, bypassInput, err := decodeReattackReport(report)
	if err != nil {
		return fmt.Errorf("parse reattack report: %w", err)
	}
	var attempt db.RemediationAttempt
	if err := w.DB.First(&attempt, *scan.RemediationAttemptID).Error; err != nil {
		return fmt.Errorf("load remediation attempt %d: %w", *scan.RemediationAttemptID, err)
	}
	if attempt.FindingID != *scan.FindingID {
		return fmt.Errorf("remediation attempt %d does not belong to finding %d", attempt.ID, *scan.FindingID)
	}

	row := db.RemediationValidation{
		FindingID:            *scan.FindingID,
		RemediationAttemptID: attempt.ID,
		ScanID:               scan.ID,
		RootCauseStatus:      parsed.Outcome,
		ValidVariants:        validVariants,
		BenignControlPassed:  parsed.BenignControl.ReachedSink && !parsed.BenignControl.Crashed,
		BypassInput:          bypassInput,
		Report:               report,
		CreatedAt:            time.Now(),
	}
	if err := w.recordRemediationValidation(attempt, row); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("reattack: remediation attempt %d -> %s", attempt.Attempt, parsed.Outcome)})
	return nil
}

func (w *Worker) recordRemediationValidation(attempt db.RemediationAttempt, row db.RemediationValidation) error {
	return w.DB.Transaction(func(tx *gorm.DB) error {
		var existing db.RemediationValidation
		lookup := tx.Where("remediation_attempt_id = ? AND scan_id = ?", attempt.ID, row.ScanID).
			Limit(1).Find(&existing)
		if lookup.Error != nil {
			return fmt.Errorf("check existing remediation validation: %w", lookup.Error)
		}
		if lookup.RowsAffected > 0 {
			return nil
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("record remediation validation: %w", err)
		}
		note := fmt.Sprintf("reattack: attempt %d\nstatus: %s\nvalid variants: %d\nbenign control passed: %t",
			attempt.Attempt, row.RootCauseStatus, row.ValidVariants, row.BenignControlPassed)
		if row.BypassInput != "" {
			note += "\n\nbypass input:\n" + row.BypassInput
		}
		if _, err := db.AddFindingNote(tx, attempt.FindingID, note, reattackSkillName); err != nil {
			return fmt.Errorf("record reattack note: %w", err)
		}
		return nil
	})
}

func decodeReattackReport(report string) (reattackReport, int, string, error) {
	var parsed reattackReport
	if err := json.Unmarshal([]byte(report), &parsed); err != nil {
		return reattackReport{}, 0, "", err
	}
	validGeneratedVariants, bypassInput, err := inspectReattackVariants(parsed.Variants)
	if err != nil {
		return reattackReport{}, 0, "", err
	}
	benignPassed := parsed.BenignControl.ReachedSink && !parsed.BenignControl.Crashed
	if err := validateReattackOutcome(parsed.Outcome, validGeneratedVariants, benignPassed, bypassInput != ""); err != nil {
		return reattackReport{}, 0, "", err
	}
	return parsed, validGeneratedVariants, bypassInput, nil
}

func inspectReattackVariants(variants []reattackVariant) (int, string, error) {
	validGeneratedVariants := 0
	bypassInput := ""
	seenGeneratedInputs := make(map[string]bool)
	for i, variant := range variants {
		if err := validateReattackVariant(i, variant); err != nil {
			return 0, "", err
		}
		if variant.Valid && variant.Origin == "generated" {
			input := strings.TrimSpace(variant.Input)
			if seenGeneratedInputs[input] {
				return 0, "", fmt.Errorf("variants[%d] duplicates a generated input", i)
			}
			seenGeneratedInputs[input] = true
			validGeneratedVariants++
		}
		if variant.Outcome == "bypassed" && bypassInput == "" {
			bypassInput = boundedBypassInput(variant.Input)
		}
	}
	return validGeneratedVariants, bypassInput, nil
}

func validateReattackVariant(index int, variant reattackVariant) error {
	if strings.TrimSpace(variant.Input) == "" {
		return fmt.Errorf("variants[%d] input must not be blank", index)
	}
	if variant.Valid && variant.Outcome == "invalid" {
		return fmt.Errorf("variants[%d] is valid but has outcome invalid", index)
	}
	if !variant.Valid && variant.Outcome != "invalid" {
		return fmt.Errorf("variants[%d] is invalid but has outcome %q", index, variant.Outcome)
	}
	if variant.Origin != "generated" && variant.Origin != "prior_bypass" {
		return fmt.Errorf("variants[%d] has invalid origin %q", index, variant.Origin)
	}
	if variant.Valid && (!variant.SameBugClass || !variant.SameSink || strings.TrimSpace(variant.Sink) == "") {
		return fmt.Errorf("variants[%d] valid input must target the same bug class and sink", index)
	}
	if variant.Outcome == "bypassed" && strings.TrimSpace(variant.FailureClass) == "" {
		return fmt.Errorf("variants[%d] bypass requires failure_class and sink", index)
	}
	return nil
}

func validateReattackOutcome(outcome string, validGeneratedVariants int, benignPassed, hasBypass bool) error {
	switch outcome {
	case db.ReattackFailedToBypass:
		if validGeneratedVariants < minReattackVariants {
			return fmt.Errorf("failed_to_bypass requires at least %d distinct valid generated variants; got %d", minReattackVariants, validGeneratedVariants)
		}
		if hasBypass {
			return fmt.Errorf("failed_to_bypass contains a valid bypass")
		}
		if !benignPassed {
			return fmt.Errorf("failed_to_bypass requires a benign input that reaches the sink without crashing")
		}
	case db.ReattackBypassedPatch:
		if !hasBypass {
			return fmt.Errorf("bypassed_patch requires a valid same-class, same-sink bypass")
		}
	case db.ReattackInconclusive:
		if hasBypass {
			return fmt.Errorf("inconclusive contains a valid bypass and must be bypassed_patch")
		}
		if validGeneratedVariants >= minReattackVariants && benignPassed {
			return fmt.Errorf("inconclusive has enough blocked variants and a passing benign control; use failed_to_bypass")
		}
	default:
		return fmt.Errorf("outcome %q is invalid", outcome)
	}
	return nil
}
