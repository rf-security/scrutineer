package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

type akritesPage struct {
	Finding     db.Finding
	Report      akrites.Report
	Disclosure  string
	Exploit     string
	Submissions []db.DisclosureSubmission
	// ShowForm is false when submission is disabled or the finding is not
	// eligible, leaving only the history of earlier submissions.
	ShowForm bool
	Endpoint string
	Error    string
}

func (p akritesPage) title() string {
	return "Akrites submission · " + p.Finding.Title
}

func (s *Server) findingAkritesPreview(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.loadDisclosureFinding(w, r)
	if !ok {
		return
	}
	page, status, msg := s.akritesPreview(ctx)
	switch status {
	case 0:
		s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": page, pageTitleKey: page.title()})
	case http.StatusNotFound:
		http.NotFound(w, r)
	default:
		http.Error(w, msg, status)
	}
}

// akritesSymbol prefills affected_symbol from the finding's location. The
// function is left for the analyst because locations name only a file and line.
func akritesSymbol(f db.Finding) *akrites.Symbol {
	file := findingnorm.FindingPath(f.SubPath, f.Location)
	if file == "" {
		return nil
	}
	return &akrites.Symbol{File: file, Line: locationLine(f.Location)}
}

// locationLine returns the line from a "path:line[:col]" or "path:start-end"
// location, or 0 when it names none.
func locationLine(location string) int {
	loc := strings.TrimSpace(strings.Split(strings.TrimSpace(location), "\n")[0])
	line := 0
	for {
		i := strings.LastIndexByte(loc, ':')
		if i < 0 || !findingnorm.IsPositionalSuffix(loc[i+1:]) {
			return line
		}
		start, _, _ := strings.Cut(loc[i+1:], "-")
		line, _ = strconv.Atoi(start)
		loc = loc[:i]
	}
}

func akritesEligibility(ctx disclosureFindingContext) error {
	if db.FindingDisclosureBlocked(ctx.Finding) {
		return db.ErrFindingNonViable
	}
	if strings.TrimSpace(ctx.Finding.DisclosureDraft) == "" {
		return fmt.Errorf("a reviewed disclosure draft is required before Akrites submission")
	}
	// A reported finding can still go to another recipient.
	switch ctx.Finding.Status {
	case db.FindingFixed, db.FindingPublished, db.FindingRejected, db.FindingDuplicate:
		return fmt.Errorf("finding status %q cannot be submitted to Akrites", ctx.Finding.Status)
	}
	for _, note := range ctx.Notes {
		first, _, _ := strings.Cut(note.Body, "\n")
		if strings.HasPrefix(strings.TrimSpace(first), "finding-dedup: subsumed by finding #") {
			return fmt.Errorf("this finding is subsumed by another finding")
		}
	}
	return nil
}

// akritesAttachments sends the disclosure draft and the exploitation details
// as attachments. Their filenames, descriptions and types are stored in the
// clear at Akrites, so they carry no finding detail.
func akritesAttachments(disclosure, exploit string) []akrites.Attachment {
	var out []akrites.Attachment
	if strings.TrimSpace(disclosure) != "" {
		out = append(out, akrites.Attachment{Filename: "disclosure.md", Data: disclosure, ContentType: "text/markdown", Description: "Disclosure report", Type: "other"})
	}
	if strings.TrimSpace(exploit) != "" {
		out = append(out, akrites.Attachment{Filename: "exploit.txt", Data: exploit, ContentType: "text/plain", Description: "Exploitation details", Type: "exploit-proof-of-concept"})
	}
	return out
}

func akritesPageFromForm(r *http.Request, finding db.Finding) akritesPage {
	page := akritesPage{Finding: finding, Disclosure: r.FormValue("raw"), Exploit: r.FormValue("exploit")}
	page.Report = akrites.Report{
		Software: strings.TrimSpace(r.FormValue("software")), PURL: strings.TrimSpace(r.FormValue("purl")),
		Ecosystem:       strings.TrimSpace(r.FormValue("ecosystem")),
		Attachments:     akritesAttachments(page.Disclosure, page.Exploit),
		PackageRepoURL:  strings.TrimSpace(r.FormValue("package_repo_url")),
		DiscoveryMethod: strings.TrimSpace(r.FormValue("discovery_method")), Email: strings.TrimSpace(r.FormValue("email")), Notify: r.FormValue("notify"),
	}
	symbol := akrites.Symbol{File: strings.TrimSpace(r.FormValue("symbol_file")), Function: strings.TrimSpace(r.FormValue("symbol_function"))}
	if line := strings.TrimSpace(r.FormValue("symbol_line")); line != "" {
		n, err := strconv.Atoi(line)
		if err != nil {
			n = -1
		}
		symbol.Line = n
	}
	if symbol != (akrites.Symbol{}) {
		page.Report.AffectedSymbol = &symbol
	}
	for v := range strings.SplitSeq(r.FormValue("versions"), "\n") {
		if v = strings.TrimSpace(v); v != "" {
			page.Report.Versions = append(page.Report.Versions, v)
		}
	}
	return page
}

func (s *Server) findingAkritesSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.Akrites.Enabled() {
		http.NotFound(w, r)
		return
	}
	// URL-encoded forms can expand each byte to three bytes.
	const formEncodingExpansion = 3
	r.Body = http.MaxBytesReader(w, r.Body, formEncodingExpansion*akrites.MaxBodySize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid or oversized form", http.StatusBadRequest)
		return
	}
	s.vinceSubmitMu.Lock()
	defer s.vinceSubmitMu.Unlock()
	ctx, ok := s.loadDisclosureFinding(w, r)
	if !ok {
		return
	}
	out := s.submitAkrites(r, ctx)
	switch {
	case out.Page != nil:
		w.WriteHeader(out.Status)
		s.render(w, r, "finding_akrites.html", map[string]any{"Akrites": *out.Page, pageTitleKey: out.Page.title()})
	case out.Kind != disclosureSubmitted:
		http.Error(w, out.Message, out.Status)
	default:
		s.redirect(w, r, fmt.Sprintf("/findings/%d/akrites", ctx.Finding.ID))
	}
}
