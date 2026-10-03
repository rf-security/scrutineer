package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestFindingRejectionRequiresDecisionAndReason(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	for _, form := range []url.Values{
		{statusKey: {"rejected"}},
		{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {" \n"}},
		{statusKey: {"rejected"}, "verdict": {"true_positive"}, "reason": {"reason"}},
	} {
		if w := postFindingStatus(t, s, f.ID, form); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d: %s", w.Code, w.Body)
		}
	}
	w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {"guard verified at parser.go:10"}, "reviewer": {"analyst"}})
	if w.Code >= 400 {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	reviews, err := db.ListFindingReviews(s.DB, f.ID)
	if err != nil || len(reviews) != 1 || reviews[0].Reviewer != "analyst" || reviews[0].SourceScanID != f.ScanID {
		t.Fatalf("reviews = %+v, %v", reviews, err)
	}
	if err := s.DB.First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingRejected {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestFindingRejectionDatabaseError(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	if err := s.DB.Exec("CREATE TRIGGER fail_review BEFORE INSERT ON finding_reviews BEGIN SELECT RAISE(ABORT, 'forced'); END").Error; err != nil {
		t.Fatal(err)
	}
	w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {"guarded"}})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if err := s.DB.First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status == db.FindingRejected {
		t.Fatal("rejected despite failed review persistence")
	}
}

func TestFindingRejectionDoesNotAffectAgreement(t *testing.T) {
	for _, verdict := range []string{"false_positive", "already_fixed", "uncertain"} {
		t.Run(verdict, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f, _ := seedAuditFixture(t, s)
			if err := s.DB.Model(&f).Update("last_revalidate_verdict", verdict).Error; err != nil {
				t.Fatal(err)
			}
			// An explicit review still contributes to calibration, unlike rejection.
			if _, err := db.AddFindingReview(s.DB, f.ID, "uncertain", "needs investigation", "uncertain", "analyst"); err != nil {
				t.Fatal(err)
			}
			form := url.Values{statusKey: {"rejected"}, "verdict": {verdict}, "reason": {"not actionable"}, "reviewer": {"analyst"}, "automated_outcome": {verdict}}
			if w := postFindingStatus(t, s, f.ID, form); w.Code >= http.StatusBadRequest {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			reviews, err := db.ListFindingReviews(s.DB, f.ID)
			if err != nil || len(reviews) != 2 {
				t.Fatalf("reviews = %v, error = %v", reviews, err)
			}
			if reviews[0].Verdict != verdict || reviews[0].AutomatedOutcome != "" {
				t.Fatalf("rejection recorded a comparison: %+v", reviews[0])
			}
			metrics, err := db.ComputeAuditMetrics(s.DB)
			if err != nil {
				t.Fatal(err)
			}
			if metrics.TotalReviews != 2 || metrics.WithAutomatedOutcome != 1 || metrics.Agreements != 1 || metrics.AgreementRate != 1 {
				t.Fatalf("rejection changed agreement metrics: %+v", metrics)
			}
		})
	}
}

func TestFindingRejectionMultibyteReason(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	if err := s.DB.Model(&f).Update("location", "parser.go:10").Error; err != nil {
		t.Fatal(err)
	}
	reason := strings.Repeat("\u00e9", db.MaxReviewReasonChars)
	form := url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {reason}}
	if w := postFindingStatus(t, s, f.ID, form); w.Code >= 400 {
		t.Fatalf("valid multibyte reason rejected: %d: %s", w.Code, w.Body)
	}
	feedback, err := db.FindingFeedbackForPaths(s.DB, f.RepositoryID, []string{"parser.go"})
	if err != nil || len(feedback) != 1 || feedback[0].Reason != reason {
		t.Fatalf("multibyte reason lost in feedback: %d entries, error = %v", len(feedback), err)
	}
	form.Set("verdict", "already_fixed")
	form.Set("reason", reason+"\u00e9")
	w := postFindingStatus(t, s, f.ID, form)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "reasons must not exceed 4096 characters") || strings.Contains(w.Body.String(), "false-positive") {
		t.Fatalf("incorrect length error: %d: %s", w.Code, w.Body)
	}
}

func TestFindingRejectionDialog(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	r := httptest.NewRequest(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(f.ID), 10), nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	for _, want := range []string{`data-dialog="reject-`, `name="verdict" required`, `name="reason" rows="3" maxlength="4096" required`, `Other / not actionable`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
