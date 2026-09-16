package web

import (
	"sort"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const migrationGuideRowLimit = 10

type findingMigrationGuide struct {
	Health db.RepositoryHealth

	Packages         []db.Package
	Alternatives     []db.PackageAlternative
	CampaignStatuses []db.DependentCampaignStatus

	PriorityDependents []migrationDependentRow
	KnownSafeCount     int
	FixedCount         int
	TotalExposureRows  int
}

type migrationDependentRow struct {
	DependentID       uint
	Name              string
	Ecosystem         string
	RepositoryURL     string
	DependentRepos    int
	Status            string
	Rationale         string
	UpdatedAt         time.Time
	CampaignStatus    db.DependentCampaignStatus
	CampaignNote      string
	CampaignUpdatedAt *time.Time
}

func loadFindingMigrationGuide(
	gdb *gorm.DB,
	repo db.Repository,
	exposureRows []db.FindingDependent,
	dependentsByID map[uint]db.Dependent,
) (*findingMigrationGuide, error) {
	alternatives, err := loadPackageAlternatives(gdb, repo.ID)
	if err != nil {
		return nil, err
	}
	if !showPackageAlternatives(repo, alternatives) {
		return nil, nil
	}

	var packages []db.Package
	if err := gdb.Where("repository_id = ?", repo.ID).
		Order("dependent_repos desc, downloads desc, id asc").
		Limit(migrationGuideRowLimit).
		Find(&packages).Error; err != nil {
		return nil, err
	}

	guide := findingMigrationGuide{
		Health:           repo.Health,
		Packages:         packages,
		Alternatives:     alternatives,
		CampaignStatuses: db.DependentCampaignStatuses,
	}
	loadMigrationGuideDependents(exposureRows, dependentsByID, &guide)
	return &guide, nil
}

func loadMigrationGuideDependents(
	exposureRows []db.FindingDependent,
	dependentsByID map[uint]db.Dependent,
	guide *findingMigrationGuide,
) {
	guide.TotalExposureRows = len(exposureRows)
	if len(exposureRows) == 0 {
		return
	}

	actionableRows := make([]migrationDependentRow, 0, len(exposureRows))
	trackedResolvedRows := make([]migrationDependentRow, 0)
	for _, row := range exposureRows {
		row.Status = migrationExposureStatus(row.Status)
		actionable := true
		if row.Status == db.ExposureKnownNotAffected {
			guide.KnownSafeCount++
			actionable = false
		}
		if row.Status == db.ExposureFixed {
			guide.FixedCount++
			actionable = false
		}
		if !actionable && row.CampaignStatus == "" {
			continue
		}
		dep, ok := dependentsByID[row.DependentID]
		if !ok {
			continue
		}
		viewRow := migrationDependentRow{
			DependentID:       dep.ID,
			Name:              dep.Name,
			Ecosystem:         dep.Ecosystem,
			RepositoryURL:     dep.RepositoryURL,
			DependentRepos:    dep.DependentRepos,
			Status:            row.Status,
			Rationale:         row.Rationale,
			UpdatedAt:         row.UpdatedAt,
			CampaignStatus:    row.CampaignStatus,
			CampaignNote:      row.CampaignNote,
			CampaignUpdatedAt: row.CampaignUpdatedAt,
		}
		if actionable {
			actionableRows = append(actionableRows, viewRow)
		} else {
			trackedResolvedRows = append(trackedResolvedRows, viewRow)
		}
	}
	sortMigrationDependentRows(actionableRows)
	sortMigrationDependentRows(trackedResolvedRows)
	if len(actionableRows) > migrationGuideRowLimit {
		actionableRows = actionableRows[:migrationGuideRowLimit]
	}
	guide.PriorityDependents = make([]migrationDependentRow, 0, len(actionableRows)+len(trackedResolvedRows))
	guide.PriorityDependents = append(guide.PriorityDependents, actionableRows...)
	guide.PriorityDependents = append(guide.PriorityDependents, trackedResolvedRows...)
}

func sortMigrationDependentRows(rows []migrationDependentRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DependentRepos != rows[j].DependentRepos {
			return rows[i].DependentRepos > rows[j].DependentRepos
		}
		return rows[i].Name < rows[j].Name
	})
}

func migrationExposureStatus(status string) string {
	if status == "" {
		return db.ExposureUnderInvestigation
	}
	return status
}
