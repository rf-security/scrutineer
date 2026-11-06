package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"scrutineer/internal/db"
)

// The status transition shared by the HTML form (POST /findings/{id}/status),
// the JSON surface (POST /api/v1/ui/findings/{id}/status) and the findings
// batch. Each caller maps the returned error onto its own response.

var (
	// errFindingReadyNeedsDraft refuses ready without a saved disclosure draft.
	errFindingReadyNeedsDraft = errors.New("a saved disclosure draft is required before marking ready")
	// errInvalidFindingStatus is an unknown lifecycle value.
	errInvalidFindingStatus = errors.New("invalid status")
	// errFederationClaimCheck is a failure to ask the federation peers.
	errFederationClaimCheck = errors.New("failed to check federation peers")
)

// federationClaimError reports that a peer holds the finding. The claim is
// recorded on the finding before this is returned, so the next attempt goes
// through (the recorded claim is the acknowledgement).
type federationClaimError struct {
	Contacts string
}

func (e *federationClaimError) Error() string {
	return ErrFederationClaimPending.Error() + ": " + e.Contacts
}

func (e *federationClaimError) Unwrap() error { return ErrFederationClaimPending }

// findingStatusInput is one requested transition. Verdict, Reason and
// Reviewer are only read for rejected; By attributes the history row of every
// other transition.
type findingStatusInput struct {
	Status   db.FindingLifecycle
	Verdict  string
	Reason   string
	Reviewer string
	By       string
}

// applyFindingStatus moves f to in.Status with the rules of the finding page:
// rejected records the analyst review atomically (db.RejectFinding), ready
// requires a saved disclosure draft, and a first move to reported asks the
// federation peers first. Errors: db.ErrInvalidFindingReview,
// errFindingReadyNeedsDraft, errInvalidFindingStatus, *federationClaimError,
// errFederationClaimCheck, db.ErrFindingNonViable, or a write error.
func (s *Server) applyFindingStatus(ctx context.Context, f db.Finding, in findingStatusInput) error {
	gdb := s.DB.WithContext(ctx)
	if in.Status == db.FindingRejected {
		return db.RejectFinding(gdb, f.ID, in.Verdict, in.Reason, in.Reviewer)
	}
	if in.Status == db.FindingReady && strings.TrimSpace(f.DisclosureDraft) == "" {
		return errFindingReadyNeedsDraft
	}
	// Nothing to ask a peer when the finding is already reported: the outreach
	// this gates has happened, and a no-op transition writes nothing, so it
	// would leave the claim it just recorded standing.
	if in.Status == db.FindingReported && f.Status != db.FindingReported {
		claims, err := s.claimPeerHold(ctx, f)
		if err != nil {
			s.Log.Error("claim-check out", "finding", f.ID, "err", err)
			return fmt.Errorf("%w: %w", errFederationClaimCheck, err)
		}
		if claims != "" {
			return &federationClaimError{Contacts: claims}
		}
	}
	switch in.Status {
	case db.FindingNew, db.FindingEnriched, db.FindingTriaged, db.FindingReady,
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished,
		db.FindingRejected, db.FindingDuplicate:
		return db.WriteFindingField(gdb, f.ID, statusKey, string(in.Status), db.SourceAnalyst, in.By)
	default:
		return errInvalidFindingStatus
	}
}

// writeFindingStatusHTMLError writes the plain-text response the finding
// page's status form has always produced for err, or redirects back to the
// finding when a peer claim was recorded (the page then shows the banner).
func (s *Server) writeFindingStatusHTMLError(w http.ResponseWriter, r *http.Request, f db.Finding, in findingStatusInput, err error) {
	var claim *federationClaimError
	switch {
	case errors.As(err, &claim):
		s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
	case in.Status == db.FindingRejected:
		http.Error(w, err.Error(), findingReviewErrorStatus(err))
	case errors.Is(err, errFindingReadyNeedsDraft), errors.Is(err, errInvalidFindingStatus):
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, errFederationClaimCheck):
		http.Error(w, errFederationClaimCheck.Error(), http.StatusInternalServerError)
	case errors.Is(err, db.ErrFindingNonViable):
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
	default:
		http.Error(w, err.Error(), findingWriteErrorStatus(err, http.StatusInternalServerError))
	}
}
