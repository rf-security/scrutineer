package web

import (
	"context"
	"fmt"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

// logDisclosureRequested records that a disclosure skill was launched against
// scan.FindingID. It runs in the scan-creating transaction so a scan that rolls
// back leaves no event behind. ctx is the launching request: a skill API launch
// carries the authenticated scan, which the event is attributed to.
func logDisclosureRequested(ctx context.Context, tx *gorm.DB, scan db.Scan, source db.FindingSource) error {
	if scan.FindingID == nil {
		return fmt.Errorf("disclosure audit event needs a finding scan")
	}
	if source == "" {
		source = db.SourceAnalyst
	}
	payload := map[string]any{
		db.AuditKeyRepositoryID: scan.RepositoryID,
		"skill_name":            scan.SkillName,
		"scan_id":               scan.ID,
	}
	// scan_id and skill_name already name the launched scan, so the calling
	// scan is recorded under its own keys rather than overwriting them.
	caller := map[string]any{}
	actor := db.AuditScanAttribution(ctx, "", caller)
	if id, ok := caller["scan_id"]; ok {
		payload["caller_scan_id"] = id
		payload["caller_skill_name"] = caller["skill_name"]
	}
	return db.LogEvent(tx, db.AuditEventInput{
		Kind: db.AuditEventDisclosureRequested, SubjectType: db.AuditSubjectFinding, SubjectID: *scan.FindingID,
		Source: source, Actor: actor, Payload: payload,
	})
}

// logScanCreated writes the operator-action event, if any, that the scan
// options ask for. Automatic enqueues set neither option and log nothing.
func logScanCreated(ctx context.Context, tx *gorm.DB, scan db.Scan, opts ScanOpts) error {
	switch {
	case opts.AuditRetry:
		return logScanControl(tx, db.AuditEventScanRetryRequested, scan, retryLineage(scan), "", db.ScanQueued, db.SourceAnalyst)
	case opts.AuditDisclosure:
		return logDisclosureRequested(ctx, tx, scan, opts.AuditSource)
	default:
		return nil
	}
}
