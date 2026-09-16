package web

import (
	"encoding/json"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type attackPathAdjustment struct {
	Kind           string `json:"kind"`
	Reason         string `json:"reason"`
	SeverityBefore string `json:"severity_before"`
	SeverityAfter  string `json:"severity_after"`
}

type attackPathReport struct {
	ProductionViability           string                 `json:"production_viability"`
	SourceState                   string                 `json:"source_state"`
	Reason                        string                 `json:"reason"`
	Counterevidence               []string               `json:"counterevidence"`
	AttackerPosition              string                 `json:"attacker_position"`
	Preconditions                 []string               `json:"preconditions"`
	Impact                        string                 `json:"impact"`
	Likelihood                    string                 `json:"likelihood"`
	AppliedAdjustments            []attackPathAdjustment `json:"applied_adjustments"`
	FactsThatWouldChangeTheResult []string               `json:"facts_that_would_change_the_result"`
}

type findingAttackPathView struct {
	db.FindingAttackPath
	Assessment attackPathReport
	Parsed     bool
}

func loadFindingAttackPathViews(gdb *gorm.DB, findingID uint) ([]findingAttackPathView, error) {
	var rows []db.FindingAttackPath
	if err := gdb.Where("finding_id = ?", findingID).Order("id desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]findingAttackPathView, 0, len(rows))
	for _, row := range rows {
		view := findingAttackPathView{FindingAttackPath: row}
		if err := json.Unmarshal([]byte(row.Report), &view.Assessment); err == nil {
			view.Parsed = true
		}
		views = append(views, view)
	}
	return views, nil
}

func findingAttackPathResponse(row *db.FindingAttackPath) map[string]any {
	var report any
	if err := json.Unmarshal([]byte(row.Report), &report); err != nil {
		report = row.Report
	}
	return map[string]any{
		"id":                   row.ID,
		"scan_id":              row.ScanID,
		"production_viability": row.ProductionViability,
		"report":               report,
		"created_at":           row.CreatedAt,
	}
}
