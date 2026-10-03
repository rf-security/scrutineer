package web

import (
	"errors"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// findingAdvisoryPackages selects published identities, not a transitive impact
// set. Narrow only when package links exist; discovery alone does not enable
// attribution. Do not infer attribution from source locations.
func findingAdvisoryPackages(gdb *gorm.DB, f db.Finding, columns []string) ([]db.Package, error) {
	var linked int64
	if err := gdb.Model(&db.Package{}).Where("repository_id = ? AND subproject_id IS NOT NULL", f.RepositoryID).Count(&linked).Error; err != nil {
		return nil, err
	}
	q := gdb.Where("repository_id = ?", f.RepositoryID)
	if linked != 0 {
		// Root/shared-code findings do not establish a package impact set.
		if f.SubPath == "" {
			return nil, nil
		}
		var sub db.Subproject
		err := gdb.Where("repository_id = ? AND path = ?", f.RepositoryID, f.SubPath).Take(&sub).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		q = q.Where("subproject_id = ?", sub.ID)
	}
	if len(columns) != 0 {
		q = q.Select(columns)
	}
	var pkgs []db.Package
	if err := q.Order("id").Find(&pkgs).Error; err != nil {
		return nil, err
	}
	return pkgs, nil
}
