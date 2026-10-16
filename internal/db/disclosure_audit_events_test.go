package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func decodePayload(t *testing.T, event AuditEvent) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func eventsOfKind(t *testing.T, gdb *gorm.DB, kind string) []AuditEvent {
	t.Helper()
	var events []AuditEvent
	if err := gdb.Where("kind = ?", kind).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func TestDisclosureDraftAudit(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	const first = "Dear maintainer, secret exploit details"
	const second = "Updated draft with café"
	for _, draft := range []string{first, first, second} {
		if err := WriteFindingField(gdb, f.ID, "disclosure_draft", draft, SourceAnalyst, ""); err != nil {
			t.Fatal(err)
		}
	}
	events := eventsOfKind(t, gdb, AuditEventDisclosureDraftUpdated)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per change", events)
	}
	for _, event := range events {
		if event.SubjectType != AuditSubjectFinding || event.SubjectID != f.ID || event.Source != SourceAnalyst {
			t.Fatalf("event = %+v", event)
		}
		if strings.Contains(event.Payload, "exploit") || strings.Contains(event.Payload, "Updated draft") {
			t.Fatalf("draft text leaked: %s", event.Payload)
		}
	}
	payload := decodePayload(t, events[1])
	if payload["old_length"] != float64(len([]rune(first))) || payload["new_length"] != float64(len([]rune(second))) ||
		payload["field"] != "disclosure_draft" || payload["repository_id"] != float64(f.RepositoryID) {
		t.Fatalf("payload = %s", events[1].Payload)
	}
}

func TestDisclosureDraftAuditScanAttribution(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	ctx := WithAuditScan(context.Background(), 42, "disclose")
	if err := WriteFindingField(gdb.WithContext(ctx), f.ID, "disclosure_draft", "skill draft", SourceModel, "claimed"); err != nil {
		t.Fatal(err)
	}
	events := eventsOfKind(t, gdb, AuditEventDisclosureDraftUpdated)
	if len(events) != 1 || events[0].Actor != "disclose (scan 42)" || events[0].Source != SourceModel {
		t.Fatalf("events = %+v", events)
	}
	payload := decodePayload(t, events[0])
	if payload["scan_id"] != float64(42) || payload["skill_name"] != "disclose" {
		t.Fatalf("payload = %s", events[0].Payload)
	}
}

func TestDisclosureCommunicationAudit(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	ctx := WithAuditScan(context.Background(), 7, "disclose")
	c, err := AddFindingCommunication(gdb.WithContext(ctx), f.ID, "email", "outbound", "alice@example.org", "private body text", "patch", time.Time{}, SourceModel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddFindingCommunication(gdb, f.ID, "github", "inbound", "bob", "ack", "", time.Time{}, SourceAnalyst); err != nil {
		t.Fatal(err)
	}
	events := eventsOfKind(t, gdb, AuditEventDisclosureCommunicationRecorded)
	if len(events) != 2 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Actor != "disclose (scan 7)" || events[0].Source != SourceModel || events[0].SubjectID != f.ID {
		t.Fatalf("event = %+v", events[0])
	}
	payload := decodePayload(t, events[0])
	if payload["communication_id"] != float64(c.ID) || payload["channel"] != "email" || payload["direction"] != "outbound" ||
		payload["offered_help"] != true || payload["scan_id"] != float64(7) || payload["repository_id"] != float64(f.RepositoryID) {
		t.Fatalf("payload = %s", events[0].Payload)
	}
	for _, event := range events {
		for _, secret := range []string{"private body text", "alice@example.org", "bob", "patch"} {
			if strings.Contains(event.Payload, secret) || strings.Contains(event.Actor, secret) {
				t.Fatalf("%q leaked: %+v", secret, event)
			}
		}
	}
	if events[1].Actor != "" || decodePayload(t, events[1])["offered_help"] != false {
		t.Fatalf("event = %+v", events[1])
	}
}

func TestDisclosureCommunicationAuditFailureRollsBack(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	injected := rejectFindingAuditWrites(t, gdb)
	if _, err := AddFindingCommunication(gdb, f.ID, "email", "outbound", "a", "b", "", time.Time{}, SourceAnalyst); !errors.Is(err, injected) {
		t.Fatalf("error = %v, want audit failure", err)
	}
	var count int64
	if err := gdb.Model(&FindingCommunication{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("communications = %d err=%v", count, err)
	}
}

func TestDisclosureChannelAudit(t *testing.T) {
	gdb := newTestDB(t)
	repo := Repository{URL: "https://example.com/chan", Name: "chan"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{" a@example.org\n", "a@example.org", "b@example.org"} {
		if err := SetDisclosureChannel(gdb, repo.ID, v, SourceModel, "maintainers"); err != nil {
			t.Fatal(err)
		}
	}
	events := eventsOfKind(t, gdb, AuditEventDisclosureChannelChanged)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per change", events)
	}
	for _, event := range events {
		if event.SubjectType != AuditSubjectRepository || event.SubjectID != repo.ID || event.Source != SourceModel || event.Actor != "maintainers" {
			t.Fatalf("event = %+v", event)
		}
	}
	payload := decodePayload(t, events[1])
	if payload["scope"] != "repository" || payload["old_value"] != "a@example.org" || payload["new_value"] != "b@example.org" ||
		payload["repository_id"] != float64(repo.ID) {
		t.Fatalf("payload = %s", events[1].Payload)
	}
	if _, ok := payload["subproject_id"]; ok {
		t.Fatalf("repository scope carries subproject: %s", events[1].Payload)
	}
}

func TestSubprojectDisclosureChannelAudit(t *testing.T) {
	gdb := newTestDB(t)
	repo := Repository{URL: "https://example.com/mono", Name: "mono"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	sub := Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a"}
	if err := gdb.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"a@example.org", " a@example.org ", ""} {
		if err := SetSubprojectDisclosureChannel(gdb, sub.ID, v, SourceAnalyst, ""); err != nil {
			t.Fatal(err)
		}
	}
	events := eventsOfKind(t, gdb, AuditEventDisclosureChannelChanged)
	if len(events) != 2 {
		t.Fatalf("events = %+v", events)
	}
	payload := decodePayload(t, events[0])
	if events[0].SubjectType != AuditSubjectRepository || events[0].SubjectID != repo.ID ||
		payload["scope"] != "subproject" || payload["subproject_id"] != float64(sub.ID) || payload["subproject_path"] != "pkg/a" ||
		payload["old_value"] != "" || payload["new_value"] != "a@example.org" {
		t.Fatalf("event = %+v", events[0])
	}
	if decodePayload(t, events[1])["new_value"] != "" {
		t.Fatalf("clear not recorded: %s", events[1].Payload)
	}
}

func TestDisclosureChannelAuditFailureRollsBack(t *testing.T) {
	gdb := newTestDB(t)
	repo := Repository{URL: "https://example.com/rb", Name: "rb", DisclosureChannel: "old@example.org"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	sub := Subproject{RepositoryID: repo.ID, Path: "p", Name: "p", DisclosureChannel: "old@example.org"}
	if err := gdb.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	injected := rejectFindingAuditWrites(t, gdb)
	if err := SetDisclosureChannel(gdb, repo.ID, "new@example.org", SourceAnalyst, ""); !errors.Is(err, injected) {
		t.Fatalf("repo error = %v", err)
	}
	if err := SetSubprojectDisclosureChannel(gdb, sub.ID, "new@example.org", SourceAnalyst, ""); !errors.Is(err, injected) {
		t.Fatalf("subproject error = %v", err)
	}
	var gotRepo Repository
	var gotSub Subproject
	if err := errors.Join(gdb.First(&gotRepo, repo.ID).Error, gdb.First(&gotSub, sub.ID).Error); err != nil {
		t.Fatal(err)
	}
	if gotRepo.DisclosureChannel != "old@example.org" || gotSub.DisclosureChannel != "old@example.org" {
		t.Fatalf("channel survived rollback: %q %q", gotRepo.DisclosureChannel, gotSub.DisclosureChannel)
	}
	if gotRepo.DisclosureChannelAt != nil {
		t.Fatalf("timestamp survived rollback: %v", gotRepo.DisclosureChannelAt)
	}
}

// A feed import replaces the channel only while it still holds the value the
// importer read. It audits only a replacement that changes the channel.
func TestImportDisclosureChannelAudit(t *testing.T) {
	gdb := newTestDB(t)
	repo := Repository{URL: "https://example.com/feed", Name: "feed"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	const feed, hint = "https://peer.example/feed.git", "peer@example.org (via https://peer.example/feed.git)"

	if applied, err := ImportDisclosureChannel(gdb, repo.ID, "", hint, SourceSystem, feed); err != nil || !applied {
		t.Fatalf("applied=%v err=%v, want the empty channel replaced", applied, err)
	}
	// Re-importing the same hint applies but changes nothing, so no event.
	if applied, err := ImportDisclosureChannel(gdb, repo.ID, hint, hint, SourceSystem, feed); err != nil || !applied {
		t.Fatalf("applied=%v err=%v on an unchanged re-import", applied, err)
	}
	// An analyst saved an address after the importer read the channel: the
	// stale expected value no longer matches, so the analyst's address stays.
	if err := SetDisclosureChannel(gdb, repo.ID, "analyst@example.org", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	if applied, err := ImportDisclosureChannel(gdb, repo.ID, hint, "other@example.org", SourceSystem, feed); err != nil || applied {
		t.Fatalf("applied=%v err=%v, want the analyst's address kept", applied, err)
	}
	var stored Repository
	gdb.First(&stored, repo.ID)
	if stored.DisclosureChannel != "analyst@example.org" {
		t.Fatalf("channel = %q, want the analyst's address", stored.DisclosureChannel)
	}

	var imported []AuditEvent
	for _, e := range eventsOfKind(t, gdb, AuditEventDisclosureChannelChanged) {
		if e.Source == SourceSystem {
			imported = append(imported, e)
		}
	}
	if len(imported) != 1 || imported[0].Actor != feed {
		t.Fatalf("feed events = %+v, want exactly one attributed to the feed", imported)
	}
	if p := decodePayload(t, imported[0]); p["old_value"] != "" || p["new_value"] != hint {
		t.Fatalf("payload = %s", imported[0].Payload)
	}
}
