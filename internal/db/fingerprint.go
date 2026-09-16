package db

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/findingnorm"
)

// FingerprintFinding returns a stable hash for deduplicating the same
// vulnerability reported across repeated scans of one repository.
//
// The inputs are the producing skill, the scan sub-path, the CWE, and the
// file path from Location with any :line:col suffix stripped. File-level
// (not line-level) matching means a finding that drifts a few lines
// between commits still dedupes; the cost is that two distinct same-CWE
// issues in the same file collide into one row. When the CWE is empty the
// title is folded in to keep distinct findings apart: a CWE-less finding
// has nothing else to distinguish it from another in the same file, so
// without the title every rule that fires on one file (e.g. zizmor's many
// per-file audits) would collapse into a single row. Findings that carry a
// CWE keep CWE+file matching, so line drift and title rewording still
// dedupe.
func FingerprintFinding(skillName, subPath, cwe, location, title string) string {
	loc := normaliseLocation(location)
	parts := []string{
		strings.ToLower(skillName),
		strings.ToLower(strings.Trim(subPath, "/")),
		strings.ToUpper(strings.TrimSpace(cwe)),
		loc,
	}
	if cwe == "" {
		parts = append(parts, strings.ToLower(strings.TrimSpace(title)))
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

// normaliseLocation strips line, line:column, and line-range suffixes from a
// location. A leading "./" is stripped so "./src/x.go" and "src/x.go" agree.
func normaliseLocation(loc string) string {
	loc = strings.TrimSpace(loc)
	loc = strings.TrimPrefix(loc, "./")
	for {
		i := strings.LastIndexByte(loc, ':')
		if i <= 0 || !findingnorm.IsPositionalSuffix(loc[i+1:]) {
			break
		}
		loc = loc[:i]
	}
	return strings.ToLower(loc)
}

// BackfillFindingFingerprints fills Finding.Fingerprint for rows created
// before the column existed, joining through Scan for skill_name. It does
// not merge existing duplicates; it just sets the column so future scans
// dedupe against them. Successful updates remain committed if a later row
// fails, and the next startup retries only unfinished rows. Safe to call on
// every startup.
func BackfillFindingFingerprints(gdb *gorm.DB) error {
	type row struct {
		ID        uint
		SubPath   string
		CWE       string
		Location  string
		Title     string
		SkillName string
	}
	var rows []row
	// Ordering is not required for correctness; it makes partial progress and
	// the first reported failing row deterministic for operators and tests.
	if err := gdb.Raw(`
		SELECT f.id, f.sub_path, f.cwe, f.location, f.title, s.skill_name
		FROM findings f JOIN scans s ON s.id = f.scan_id
		WHERE f.fingerprint IS NULL OR f.fingerprint = ''
		ORDER BY f.id
	`).Scan(&rows).Error; err != nil {
		return fmt.Errorf("select findings for fingerprint backfill: %w", err)
	}
	for _, r := range rows {
		fp := FingerprintFinding(r.SkillName, r.SubPath, r.CWE, r.Location, r.Title)
		if err := gdb.Model(&Finding{}).Where("id = ?", r.ID).
			Updates(map[string]any{
				"fingerprint":       fp,
				"last_seen_scan_id": gorm.Expr("COALESCE(NULLIF(last_seen_scan_id, 0), scan_id)"),
				"last_seen_commit":  gorm.Expr(`COALESCE(NULLIF(last_seen_commit, ''), "commit")`),
				"seen_count":        gorm.Expr("CASE WHEN seen_count = 0 THEN 1 ELSE seen_count END"),
			}).Error; err != nil {
			return fmt.Errorf("update fingerprint for finding %d: %w", r.ID, err)
		}
	}
	return nil
}
