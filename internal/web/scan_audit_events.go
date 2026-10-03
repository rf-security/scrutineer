package web

import (
	"errors"
	"fmt"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const scanAuditRepositoryID = "repository_id"

func (s *Server) scanEnqueueFailure(scan db.Scan, queueErr error, auditRetry bool) error {
	enqueueErr := fmt.Errorf("enqueue scan %d: %w", scan.ID, queueErr)
	now := time.Now()
	markErr := s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).
			Updates(scanStatusUpdates(db.ScanFailed, enqueueErr.Error(), &now, nil))
		if result.Error != nil || result.RowsAffected == 0 {
			return result.Error
		}
		if auditRetry {
			return logScanControl(tx, db.AuditEventScanRetryEnqueueFailed, scan, retryLineage(scan), db.ScanQueued, db.ScanFailed, db.SourceSystem)
		}
		return nil
	})
	if markErr != nil {
		return errors.Join(enqueueErr, fmt.Errorf("mark scan failed: %w", markErr))
	}
	return enqueueErr
}

// scanLineage is the retry ancestry a scan-control event records. Only retry
// events carry it; cancel, pause, resume and bulk events pass none by design.
// Taking it explicitly keeps the payload independent of which columns the
// caller happened to load.
type scanLineage struct {
	parentScanID, resumedFromScanID *uint
}

func retryLineage(scan db.Scan) scanLineage {
	return scanLineage{parentScanID: scan.ParentScanID, resumedFromScanID: scan.ResumedFromScanID}
}

// logScanControl reads only scan.ID and scan.RepositoryID from scan; lineage
// comes from the explicit argument.
func logScanControl(tx *gorm.DB, kind string, scan db.Scan, lineage scanLineage, oldStatus, newStatus db.ScanStatus, source db.FindingSource) error {
	payload := map[string]any{
		scanAuditRepositoryID: scan.RepositoryID,
		"old_status":          oldStatus,
		"new_status":          newStatus,
	}
	if lineage.parentScanID != nil {
		payload["parent_scan_id"] = *lineage.parentScanID
	}
	if lineage.resumedFromScanID != nil {
		payload["resumed_from_scan_id"] = *lineage.resumedFromScanID
	}
	return db.LogEvent(tx, db.AuditEventInput{
		Kind: kind, SubjectType: db.AuditSubjectScan, SubjectID: scan.ID,
		Source: source, Payload: payload,
	})
}

func (s *Server) cancelIdleScanWithAudit(id uint, reason string, source db.FindingSource) (bool, error) {
	var changed bool
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var live db.Scan
		if err := tx.Select("id", scanAuditRepositoryID, "status").First(&live, id).Error; err != nil {
			return err
		}
		if live.Status != db.ScanQueued && live.Status != db.ScanRunning {
			return nil
		}
		now := time.Now()
		result := tx.Model(&db.Scan{}).Where("id = ? AND status = ?", id, live.Status).
			Updates(scanStatusUpdates(db.ScanCancelled, reason, &now, nil))
		if result.Error != nil || result.RowsAffected == 0 {
			return result.Error
		}
		changed = true
		return logScanControl(tx, db.AuditEventScanCancelled, live, scanLineage{}, live.Status, db.ScanCancelled, source)
	})
	if err != nil {
		return false, err
	}
	if changed {
		s.settleCancelledScanGroups(id)
	}
	return changed, nil
}

// Returning limits events to rows actually changed by the guarded update, not
// an earlier snapshot that a worker may have claimed in the meantime.
func updateScansWithAudit(base *gorm.DB, updates map[string]any, kind string, oldStatus, newStatus db.ScanStatus, source db.FindingSource) ([]db.Scan, error) {
	var changed []db.Scan
	err := base.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&changed).Clauses(clause.Returning{Columns: []clause.Column{
			{Name: "id"}, {Name: scanAuditRepositoryID},
		}}).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		for _, scan := range changed {
			if err := logScanControl(tx.Session(&gorm.Session{NewDB: true}), kind, scan, scanLineage{}, oldStatus, newStatus, source); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return changed, nil
}

// cancelScanWithAudit aborts one non-terminal scan, recording reason as the
// row's error whichever path stops it. A running scan is signalled through the
// worker, which carries the reason through to the row it writes and publishes
// scan-status as it unwinds; a scan that is not in flight is flipped here and
// reported as changed so the caller can publish a scan-status event itself.
// An audit-write failure is returned, never logged and dropped: the cancel did
// not happen, so the caller must not report it as done.
func (s *Server) cancelScanWithAudit(scan *db.Scan, reason string) (bool, error) {
	source := db.SourceSystem
	if reason == worker.CancelledByUser {
		source = db.SourceAnalyst
	}
	handled, err := s.Worker.CancelWithAudit(scan.ID, reason, func() error {
		return s.DB.Transaction(func(tx *gorm.DB) error {
			var live db.Scan
			if err := tx.Select("id", scanAuditRepositoryID, "status").First(&live, scan.ID).Error; err != nil {
				return err
			}
			if live.Status.Terminal() || live.Status == db.ScanPaused {
				return nil
			}
			return logScanControl(tx, db.AuditEventScanCancelRequested, live, scanLineage{}, live.Status, live.Status, source)
		})
	})
	if handled || err != nil {
		return false, err
	}
	return s.cancelIdleScanWithAudit(scan.ID, reason, source)
}
