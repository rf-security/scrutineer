package worker

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestParseMaintainersDisclosureChannelAudit(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	gdb.Create(&sub)
	scan := db.Scan{RepositoryID: repo.ID, SkillName: "maintainers"}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: true}
	report := `{"maintainers":[],"disclosure_channel":"repo@example.org","subprojects":[{"path":"activesupport","disclosure_channel":"as@example.org"},{"path":"missing","disclosure_channel":"x@example.org"}]}`
	for range 2 {
		if err := w.parseMaintainersOutput(&scan, report, func(Event) {}); err != nil {
			t.Fatal(err)
		}
	}
	var events []db.AuditEvent
	if err := gdb.Where("kind = ?", db.AuditEventDisclosureChannelChanged).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per real change", events)
	}
	for _, event := range events {
		if event.SubjectType != db.AuditSubjectRepository || event.SubjectID != repo.ID || event.Source != db.SourceModel || event.Actor != "maintainers" {
			t.Fatalf("event = %+v", event)
		}
	}
	var repoPayload, subPayload map[string]any
	if err := json.Unmarshal([]byte(events[0].Payload), &repoPayload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(events[1].Payload), &subPayload); err != nil {
		t.Fatal(err)
	}
	if repoPayload["scope"] != "repository" || repoPayload["new_value"] != "repo@example.org" {
		t.Fatalf("repo payload = %s", events[0].Payload)
	}
	if subPayload["scope"] != "subproject" || subPayload["subproject_id"] != float64(sub.ID) || subPayload["new_value"] != "as@example.org" {
		t.Fatalf("subproject payload = %s", events[1].Payload)
	}
}
