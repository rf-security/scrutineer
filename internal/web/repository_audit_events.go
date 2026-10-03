package web

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
)

func (s *Server) createRepositoryWithAudit(ctx context.Context, repo *db.Repository) (bool, error) {
	var created bool
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		created, err = insertRepositoryWithAudit(tx, repo)
		return err
	})
	return created && err == nil, err
}

// insertRepositoryWithAudit participates in the caller's mutation transaction.
func insertRepositoryWithAudit(tx *gorm.DB, repo *db.Repository) (bool, error) {
	insert := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "url"}}, DoNothing: true,
	}).Create(repo)
	if insert.Error != nil {
		return false, insert.Error
	}
	if insert.RowsAffected == 0 {
		return false, tx.Where("url = ?", repo.URL).First(repo).Error
	}
	if err := logRepositoryMutation(tx, db.AuditEventRepositoryCreated, *repo); err != nil {
		return false, err
	}
	return true, nil
}

func deleteRepositoryWithAudit(tx *gorm.DB, repo db.Repository) error {
	result := tx.Delete(&repo)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return logRepositoryMutation(tx, db.AuditEventRepositoryDeleted, repo)
}

func logRepositoryMutation(tx *gorm.DB, kind string, repo db.Repository) error {
	// These shared paths are operator-initiated. There is no authenticated
	// operator identity; URLs and configuration may contain secrets.
	return db.LogEvent(tx, db.AuditEventInput{
		Kind: kind, SubjectType: db.AuditSubjectRepository, SubjectID: repo.ID,
		Source: db.SourceAnalyst,
		Payload: map[string]any{
			"repository_id": repo.ID,
			"name":          repo.Name,
			"full_name":     repo.FullName,
		},
	})
}
