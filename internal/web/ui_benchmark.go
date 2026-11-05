package web

import (
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// GET /api/v1/ui/benchmark (02 #82, F-BENCH-01/02): recall/precision against
// the expected findings, one row per repository that has any. Not paginated,
// as on the HTML page.

// uiBenchmarkRepo names the repository a benchmark row scores.
type uiBenchmarkRepo struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	URL      string `json:"url"`
}

// uiBenchmarkScan is the scan a row was scored against; nil when the
// repository has no matching completed scan.
type uiBenchmarkScan struct {
	ID         uint          `json:"id"`
	SkillName  string        `json:"skill_name"`
	Model      string        `json:"model"`
	Status     db.ScanStatus `json:"status"`
	FinishedAt *time.Time    `json:"finished_at"`
}

type uiBenchmarkRow struct {
	Repository uiBenchmarkRepo  `json:"repository"`
	Scan       *uiBenchmarkScan `json:"scan"`
	benchmarkRow
}

func (s *Server) uiBenchmark(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, totals := loadBenchmarkRows(s.DB,
		strings.TrimSpace(q.Get("skill")), strings.TrimSpace(q.Get("model")), strings.TrimSpace(q.Get("harness")))
	out := make([]uiBenchmarkRow, len(rows))
	for i, row := range rows {
		out[i] = uiBenchmarkRow{
			Repository: uiBenchmarkRepo{
				ID: row.Repo.ID, Name: row.Repo.Name, FullName: row.Repo.FullName, URL: row.Repo.URL,
			},
			benchmarkRow: row,
		}
		if sc := row.Scan; sc != nil {
			out[i].Scan = &uiBenchmarkScan{
				ID: sc.ID, SkillName: sc.SkillName, Model: sc.Model, Status: sc.Status, FinishedAt: sc.FinishedAt,
			}
		}
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"totals": totals, "rows": out})
}
