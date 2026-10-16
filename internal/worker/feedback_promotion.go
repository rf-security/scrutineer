package worker

import (
	"encoding/json"
	"fmt"

	"scrutineer/internal/db"
	"scrutineer/internal/feedbackpromotion"
	"scrutineer/internal/findingnorm"
)

// FeedbackPromotionCommits is how many distinct commits, other than the one the
// analyst reviewed, must independently confirm a decision before the host
// promotes it into the repository threat model.
const FeedbackPromotionCommits = 3

// reliedReviewIDs returns the distinct positive review IDs a revalidate report
// or a deep-dive ruled_out entry lists in analyst_feedback_ids. Only that
// structured field counts: a mention of a decision in the free-text reason,
// even one saying it was not reused, records nothing.
func reliedReviewIDs(ids []uint) []uint {
	var out []uint
	seen := map[uint]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// recordFeedbackConfirmations counts a false_positive revalidate that relied on
// eligible analyst feedback and promotes decisions that reach the threshold.
// Bookkeeping failures are reported as events so they never lose the verdict.
func (w *Worker) recordFeedbackConfirmations(scan *db.Scan, f *db.Finding, relied []uint, emit func(Event)) {
	if err := w.confirmFeedback(scan, f, relied, emit); err != nil {
		emit(Event{Kind: KindError, Text: "analyst feedback confirmation: " + err.Error()})
	}
}

func (w *Worker) confirmFeedback(scan *db.Scan, f *db.Finding, relied []uint, emit func(Event)) error {
	ids := reliedReviewIDs(relied)
	path := findingnorm.FindingPath(f.SubPath, f.Location)
	if len(ids) == 0 || scan.Commit == "" || path == "" {
		return nil
	}
	eligible, err := db.EligibleFeedbackForReviews(w.DB, f.RepositoryID, path, ids)
	if err != nil {
		return fmt.Errorf("load relied feedback: %w", err)
	}
	for _, review := range eligible {
		if review.FindingID == f.ID {
			continue
		}
		if err := w.confirmReview(scan, f.RepositoryID, f.ID, db.FeedbackSourceRevalidate, review, emit); err != nil {
			return err
		}
	}
	return nil
}

// confirmReview records one confirmation of review by scan and promotes the
// decision once enough independent commits agree. findingID is the finding the
// confirming scan revalidated or, for a deep dive, the review's own finding.
func (w *Worker) confirmReview(scan *db.Scan, repoID, findingID uint, source string, review db.FindingFeedback, emit func(Event)) error {
	c := db.FeedbackConfirmation{ReviewID: review.ReviewID, ScanID: scan.ID, FindingID: findingID, Commit: scan.Commit, Source: source}
	if _, err := db.RecordFeedbackConfirmation(w.DB, &c); err != nil {
		return fmt.Errorf("record confirmation for review %d: %w", review.ReviewID, err)
	}
	confirmations, err := db.FeedbackConfirmations(w.DB, review.ReviewID)
	if err != nil {
		return fmt.Errorf("load confirmations for review %d: %w", review.ReviewID, err)
	}
	n := db.DistinctConfirmedCommits(confirmations, review.SourceCommit)
	emit(Event{Kind: KindText, Text: fmt.Sprintf("analyst feedback %d confirmed at %s (%d/%d commits)", review.ReviewID, scan.Commit, n, FeedbackPromotionCommits)})
	if n < FeedbackPromotionCommits {
		return nil
	}
	// Deep-dive confirmations add commits but never promote on their own.
	if !db.HasRevalidateConfirmation(confirmations, review.SourceCommit) {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("analyst feedback %d promotion waits for a revalidate confirmation", review.ReviewID)})
		return nil
	}
	return w.promoteFeedback(repoID, review, confirmations, emit)
}

// deepDiveFeedbackReport is the part of a security-deep-dive report that can
// confirm analyst feedback: the inventory locates each sink and a ruled_out
// entry names the decisions it relied on.
type deepDiveFeedbackReport struct {
	Inventory []struct {
		ID       string `json:"id"`
		Location string `json:"location"`
	} `json:"inventory"`
	RuledOut []struct {
		Sinks              []string `json:"sinks"`
		AnalystFeedbackIDs []uint   `json:"analyst_feedback_ids"`
	} `json:"ruled_out"`
}

// recordDeepDiveFeedbackConfirmations counts diff-mode deep-dive ruled_out
// entries that relied on eligible analyst feedback for a sink in the decision's
// file. Bookkeeping failures are reported as events so they never fail the
// parse.
func (w *Worker) recordDeepDiveFeedbackConfirmations(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) {
	if skill.Name != deepDiveSkillName || scan.RescanMode != db.ScanRescanModeDiff || scan.Commit == "" {
		return
	}
	if err := w.confirmDeepDiveFeedback(scan, report, emit); err != nil {
		emit(Event{Kind: KindError, Text: "analyst feedback confirmation: " + err.Error()})
	}
}

func (w *Worker) confirmDeepDiveFeedback(scan *db.Scan, report string, emit func(Event)) error {
	var rep deepDiveFeedbackReport
	if err := json.Unmarshal([]byte(report), &rep); err != nil {
		return fmt.Errorf("decode ruled_out: %w", err)
	}
	sinkPaths := map[string]string{}
	for _, s := range rep.Inventory {
		if p := findingnorm.FindingPath(scan.SubPath, s.Location); p != "" {
			sinkPaths[s.ID] = p
		}
	}
	// Each cited review maps to the files of the sinks of every entry citing it.
	cited := map[uint]map[string]bool{}
	var all []uint
	for _, entry := range rep.RuledOut {
		for _, id := range reliedReviewIDs(entry.AnalystFeedbackIDs) {
			if cited[id] == nil {
				cited[id] = map[string]bool{}
				all = append(all, id)
			}
			for _, sink := range entry.Sinks {
				if p := sinkPaths[sink]; p != "" {
					cited[id][p] = true
				}
			}
		}
	}
	eligible, err := db.EligibleFeedbackByReviewIDs(w.DB, scan.RepositoryID, all)
	if err != nil {
		return fmt.Errorf("load relied feedback: %w", err)
	}
	for _, review := range eligible {
		if !cited[review.ReviewID][review.Path] {
			continue
		}
		if err := w.confirmReview(scan, scan.RepositoryID, review.FindingID, db.FeedbackSourceDeepDive, review, emit); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) promoteFeedback(repoID uint, review db.FindingFeedback, confirmations []db.FeedbackConfirmation, emit func(Event)) error {
	var finding db.Finding
	if err := w.DB.Select("id, title").First(&finding, review.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d for promotion: %w", review.FindingID, err)
	}
	entry := feedbackpromotion.NewEntry(feedbackpromotion.Source{
		ReviewID: review.ReviewID, FindingID: review.FindingID, SourceCommit: review.SourceCommit,
		CWE: review.CWE, Path: review.Path, Title: finding.Title, Reason: review.Reason,
		Confirmations: promotionConfirmations(confirmations),
	})
	// Eligibility is re-read inside the compare-and-swap on every attempt: the
	// analyst may reopen or supersede the decision after it was selected.
	noModel, retired := false, false
	err := db.UpdateThreatModel(w.DB, repoID, func(previous string) (string, error) {
		noModel, retired = !feedbackpromotion.IsObject(previous), false
		if noModel {
			return previous, nil
		}
		eligible, err := db.EligibleFeedbackReviewIDs(w.DB, repoID)
		if err != nil {
			return "", err
		}
		tidied := feedbackpromotion.Filter(previous, func(id uint) bool { return eligible[id] })
		if retired = !eligible[review.ReviewID]; retired {
			return tidied, nil
		}
		return feedbackpromotion.Merge(tidied, entry)
	})
	if err != nil {
		return fmt.Errorf("promote review %d: %w", review.ReviewID, err)
	}
	switch {
	case noModel:
		emit(Event{Kind: KindText, Text: fmt.Sprintf("analyst feedback %d ready but the repository has no threat-model object; promotion deferred", review.ReviewID)})
		return nil
	case retired:
		emit(Event{Kind: KindText, Text: fmt.Sprintf("analyst feedback %d is no longer eligible; promotion skipped", review.ReviewID)})
		return nil
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("analyst feedback %d promoted into known_non_findings", review.ReviewID)})
	return nil
}

func promotionConfirmations(rows []db.FeedbackConfirmation) []feedbackpromotion.Confirmation {
	out := make([]feedbackpromotion.Confirmation, 0, len(rows))
	for _, c := range rows {
		out = append(out, feedbackpromotion.Confirmation{ScanID: c.ScanID, Commit: c.Commit})
	}
	return out
}

// activeThreatModel drops promoted entries whose decision is no longer
// eligible, so a reopened or superseded decision never suppresses anything
// even before the stored contract is tidied.
func (w *Worker) activeThreatModel(repoID uint, model, skillName string) (string, error) {
	if !feedbackpromotion.HasPromoted(model) {
		return model, nil
	}
	// The threat-model skill must not see promotions at all. It could re-emit
	// one without promoted_from, which Preserve would then keep as a
	// model-authored item no staging filter retires. Preserve re-adds the
	// host's own entries from the previous contract on refresh.
	if skillName == threatModelSkillName {
		return feedbackpromotion.StripPromoted(model), nil
	}
	eligible, err := db.EligibleFeedbackReviewIDs(w.DB, repoID)
	if err != nil {
		return "", err
	}
	return feedbackpromotion.Filter(model, func(id uint) bool { return eligible[id] }), nil
}
