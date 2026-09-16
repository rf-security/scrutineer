package coverage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ReportMetadataKey is the top-level report property advertised to skills
// that can return coverage evidence.
const ReportMetadataKey = "coverage"

// Claim is the skill-owned part of a coverage Record. Scope, scan modes,
// fallback details, threat-model state and completeness are deliberately not
// represented here: the worker owns those fields and derives completeness by
// reconciling this evidence against the scope it staged.
type Claim struct {
	Receipts        []Receipt        `json:"receipts"`
	Surfaces        []Surface        `json:"surfaces,omitempty"`
	OpenQuestions   []string         `json:"open_questions,omitempty"`
	DroppedFindings []DroppedFinding `json:"dropped_findings,omitempty"`
}

// ParseClaim decodes one untrusted skill claim. Unknown fields and trailing
// JSON are rejected so misspelled evidence cannot silently disappear.
func ParseClaim(raw json.RawMessage) (Claim, error) {
	var claim Claim
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claim); err != nil {
		return Claim{}, fmt.Errorf("decode coverage claim: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Claim{}, errors.New("coverage claim must contain one JSON object")
	}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

// Validate checks the skill-owned evidence before any of it is copied into a
// persisted coverage record.
func (claim Claim) Validate() error {
	if err := validateReceipts(claim.Receipts); err != nil {
		return err
	}
	if err := validateSurfaces(claim.Surfaces); err != nil {
		return err
	}
	if err := validateOpenQuestions(claim.OpenQuestions); err != nil {
		return err
	}
	return validateDroppedFindings(claim.DroppedFindings)
}

func validateReceipts(receipts []Receipt) error {
	if receipts == nil {
		return fmt.Errorf("coverage receipts is required")
	}
	seenPaths := make(map[string]struct{}, len(receipts))
	for i, receipt := range receipts {
		if !repositoryRelativePath(receipt.Path) {
			return fmt.Errorf("coverage receipts[%d].path must be a normalized repository-relative path", i)
		}
		if _, duplicate := seenPaths[receipt.Path]; duplicate {
			return fmt.Errorf("coverage receipts[%d].path duplicates %q", i, receipt.Path)
		}
		seenPaths[receipt.Path] = struct{}{}
		if !validDisposition(receipt.Disposition) {
			return fmt.Errorf("coverage receipts[%d].disposition %q is invalid", i, receipt.Disposition)
		}
		if dispositionNeedsReason(receipt.Disposition) && strings.TrimSpace(receipt.Reason) == "" {
			return fmt.Errorf("coverage receipts[%d].reason is required for %s", i, receipt.Disposition)
		}
	}
	return nil
}

func validateSurfaces(surfaces []Surface) error {
	seenSurfaces := make(map[string]struct{}, len(surfaces))
	for i, surface := range surfaces {
		name := strings.TrimSpace(surface.Name)
		if name == "" {
			return fmt.Errorf("coverage surfaces[%d].name must not be blank", i)
		}
		if _, duplicate := seenSurfaces[name]; duplicate {
			return fmt.Errorf("coverage surfaces[%d].name duplicates %q", i, name)
		}
		seenSurfaces[name] = struct{}{}
		if !validDisposition(surface.Disposition) {
			return fmt.Errorf("coverage surfaces[%d].disposition %q is invalid", i, surface.Disposition)
		}
		if strings.TrimSpace(surface.EvidenceRef) == "" {
			return fmt.Errorf("coverage surfaces[%d].evidence_ref must not be blank", i)
		}
	}
	return nil
}

func validateOpenQuestions(questions []string) error {
	for i, question := range questions {
		if strings.TrimSpace(question) == "" {
			return fmt.Errorf("coverage open_questions[%d] must not be blank", i)
		}
	}
	return nil
}

func validateDroppedFindings(droppedFindings []DroppedFinding) error {
	for i, dropped := range droppedFindings {
		if dropped.Path != "" && !repositoryRelativePath(dropped.Path) {
			return fmt.Errorf("coverage dropped_findings[%d].path must be a normalized repository-relative path", i)
		}
		if strings.TrimSpace(dropped.Fingerprint) == "" && dropped.Path == "" {
			return fmt.Errorf("coverage dropped_findings[%d] must identify a fingerprint or path", i)
		}
		if strings.TrimSpace(dropped.Reason) == "" {
			return fmt.Errorf("coverage dropped_findings[%d].reason must not be blank", i)
		}
	}
	return nil
}

// ApplyClaim replaces only the skill-owned fields, then asks the worker-owned
// record to derive completeness from the supplied scope.
func (rec *Record) ApplyClaim(claim Claim, scope []string) []string {
	rec.Receipts = append([]Receipt(nil), claim.Receipts...)
	rec.Surfaces = append([]Surface(nil), claim.Surfaces...)
	rec.OpenQuestions = append([]string(nil), claim.OpenQuestions...)
	rec.DroppedFindings = append([]DroppedFinding(nil), claim.DroppedFindings...)
	rec.Reason = ""
	return rec.Reconcile(scope)
}

func validDisposition(disposition string) bool {
	switch disposition {
	case DispositionReviewedClean, DispositionReviewedFindings,
		DispositionSupporting, DispositionDeferred, DispositionExcluded,
		DispositionFailed, DispositionCostCapped:
		return true
	}
	return false
}

func dispositionNeedsReason(disposition string) bool {
	switch disposition {
	case DispositionDeferred, DispositionExcluded, DispositionFailed, DispositionCostCapped:
		return true
	}
	return false
}

func repositoryRelativePath(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "/") ||
		strings.ContainsRune(value, '\\') || strings.ContainsRune(value, 0) {
		return false
	}
	parts := strings.Split(value, "/")
	if windowsDrivePrefix(parts[0]) {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func windowsDrivePrefix(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	return (value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')
}
