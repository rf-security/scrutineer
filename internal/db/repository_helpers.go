package db

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// FederationNotOptedOut is the SQL predicate for a repository whose
// maintainer has not asked federated instances to leave it alone. Every
// query that must honour an opt-out shares this text so a sixth surface
// cannot be written with a subtly different one.
const FederationNotOptedOut = "repositories.federation_opt_out_at IS NULL"

// FederationHasOptedOut is its inverse, for the queries that select the
// opted-out repositories rather than exclude them: the public feed's optout
// records and the bulk-resume subquery. Same reason as above, one text.
const FederationHasOptedOut = "repositories.federation_opt_out_at IS NOT NULL"

// FederationOptedOut reports whether this repository's maintainer asked
// federated instances neither to scan it nor to contact them. The Go-side
// counterpart of FederationNotOptedOut, for the paths that hold a loaded
// row rather than a query.
func (r Repository) FederationOptedOut() bool { return r.FederationOptOutAt != nil }

// SetDisclosureChannel writes a repository's disclosure channel and, only
// when the value actually changes, stamps DisclosureChannelAt. That
// timestamp is published as verified_at on the interchange route record, so
// bumping it on an unchanged re-write would rewrite the record and churn
// the public feed with no new information.
//
// The comparison reads the stored value in the same transaction as the write
// rather than trusting a row the caller loaded earlier: the maintainers skill
// hands over a repository it read when the scan started, which an analyst may
// have edited during the hour since.
//
// The value is trimmed here rather than at each call site: the skill hands
// over whatever the model emitted, so an answer that differs from the stored
// one only by a trailing newline would otherwise read as a change, re-stamp
// the timestamp, and republish the route record it exists to hold still.
//
// A change appends a disclosure.channel_changed event in the same transaction.
// Channels are published security contacts rather than secrets so both values
// are kept in the payload.
func SetDisclosureChannel(gdb *gorm.DB, repoID uint, value string, source FindingSource, actor string) error {
	value = strings.TrimSpace(value)
	return gdb.Transaction(func(tx *gorm.DB) error {
		var repo Repository
		if err := tx.Select("id, disclosure_channel").First(&repo, repoID).Error; err != nil {
			return err
		}
		updates := map[string]any{"disclosure_channel": value}
		changed := repo.DisclosureChannel != value
		if changed {
			now := time.Now().UTC()
			updates["disclosure_channel_at"] = &now
		}
		if err := tx.Model(&Repository{}).Where("id = ?", repoID).Updates(updates).Error; err != nil {
			return err
		}
		if !changed {
			return nil
		}
		return logDisclosureChannelChange(tx, repoID, map[string]any{"scope": "repository"}, repo.DisclosureChannel, value, source, actor)
	})
}

// ImportDisclosureChannel replaces the repository channel with one imported
// from a federation feed, but only while the stored channel still equals
// expected: an analyst or the maintainers skill may have written it since the
// caller read it. Their address must win. The timestamp is cleared because
// a peer's hint is not a route this instance verified. A replacement that
// changes the channel appends a disclosure.channel_changed event in the same
// transaction. It reports whether the stored channel was replaced.
func ImportDisclosureChannel(gdb *gorm.DB, repoID uint, expected, value string, source FindingSource, actor string) (bool, error) {
	applied := false
	err := gdb.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&Repository{}).Where("id = ? AND disclosure_channel = ?", repoID, expected).
			Updates(map[string]any{"disclosure_channel": value, "disclosure_channel_at": nil})
		if res.Error != nil {
			return res.Error
		}
		applied = res.RowsAffected > 0
		if !applied || expected == value {
			return nil
		}
		return logDisclosureChannelChange(tx, repoID, map[string]any{"scope": "repository"}, expected, value, source, actor)
	})
	return applied, err
}

// SetSubprojectDisclosureChannel writes a sub-package's own disclosure channel
// and appends a disclosure.channel_changed event, on the repository, only when
// the trimmed value differs from the stored one.
func SetSubprojectDisclosureChannel(gdb *gorm.DB, subprojectID uint, value string, source FindingSource, actor string) error {
	value = strings.TrimSpace(value)
	return gdb.Transaction(func(tx *gorm.DB) error {
		var sub Subproject
		if err := tx.Select("id, repository_id, path, disclosure_channel").First(&sub, subprojectID).Error; err != nil {
			return err
		}
		if sub.DisclosureChannel == value {
			return nil
		}
		if err := tx.Model(&Subproject{}).Where("id = ?", sub.ID).Update("disclosure_channel", value).Error; err != nil {
			return err
		}
		scope := map[string]any{"scope": "subproject", "subproject_id": sub.ID, "subproject_path": sub.Path}
		return logDisclosureChannelChange(tx, sub.RepositoryID, scope, sub.DisclosureChannel, value, source, actor)
	})
}

func logDisclosureChannelChange(tx *gorm.DB, repoID uint, payload map[string]any, oldValue, newValue string, source FindingSource, actor string) error {
	payload[AuditKeyRepositoryID] = repoID
	payload["old_value"] = oldValue
	payload["new_value"] = newValue
	return LogEvent(tx, AuditEventInput{
		Kind: AuditEventDisclosureChannelChanged, SubjectType: AuditSubjectRepository, SubjectID: repoID,
		Source: source, Actor: actor, Payload: payload,
	})
}
