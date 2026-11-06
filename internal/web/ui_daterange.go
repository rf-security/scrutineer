package web

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"gorm.io/gorm"
)

// The `date_from` / `date_to` filters of the /api/v1/ui lists that have a Date
// column (scans, findings and the repository Scans/Findings tabs). Both bound
// the row's created_at. A value is RFC3339 (any offset, fractional seconds
// allowed) or a bare YYYY-MM-DD, read as a UTC calendar day: date_from=D
// starts at D 00:00, date_to=D includes the whole of D (it ends before the
// next midnight). Clients that want local-time days send RFC3339 with their
// offset. The HTML UI never sends these keys.

const (
	uiParamDateFrom = "date_from"
	uiParamDateTo   = "date_to"
	uiDateOnly      = "2006-01-02"
	// uiSortDate is the list sort token for created_at (id tiebreak).
	uiSortDate = "date"
)

// uiDateRange is a parsed created_at window. A zero bound is open.
type uiDateRange struct {
	from time.Time
	// to is exclusive when toExclusive (a date-only date_to, moved to the next
	// midnight), inclusive otherwise (an RFC3339 instant).
	to          time.Time
	toExclusive bool
}

// parseUIDateBound parses one bound; dateOnly reports a YYYY-MM-DD value.
func parseUIDateBound(key, raw string) (t time.Time, dateOnly bool, err error) {
	if t, err = time.Parse(uiDateOnly, raw); err == nil {
		return t, true, nil
	}
	if t, err = time.Parse(time.RFC3339, raw); err == nil {
		return t, false, nil
	}
	return time.Time{}, false, fmt.Errorf("%s must be RFC3339 or YYYY-MM-DD, got %q", key, raw)
}

var errUIDateOrder = errors.New("date_from must not be after date_to")

// parseUIDateRange reads date_from / date_to from q.
func parseUIDateRange(q url.Values) (uiDateRange, error) {
	var d uiDateRange
	if raw := q.Get(uiParamDateFrom); raw != "" {
		t, _, err := parseUIDateBound(uiParamDateFrom, raw)
		if err != nil {
			return d, err
		}
		d.from = t
	}
	if raw := q.Get(uiParamDateTo); raw != "" {
		t, dateOnly, err := parseUIDateBound(uiParamDateTo, raw)
		if err != nil {
			return d, err
		}
		if dateOnly {
			t, d.toExclusive = t.AddDate(0, 0, 1), true
		}
		d.to = t
	}
	if !d.from.IsZero() && !d.to.IsZero() && (d.from.After(d.to) || (d.toExclusive && !d.from.Before(d.to))) {
		return d, errUIDateOrder
	}
	return d, nil
}

// apply bounds column (a TRUSTED constant such as "scans.created_at") to the
// window. Bounds bind in the server's local zone, the zone GORM writes
// time.Now() in, so SQLite's text timestamps compare like for like (Postgres
// compares instants either way).
func (d uiDateRange) apply(q *gorm.DB, column string) *gorm.DB {
	if !d.from.IsZero() {
		q = q.Where(column+" >= ?", d.from.Local())
	}
	if !d.to.IsZero() {
		if d.toExclusive {
			q = q.Where(column+" < ?", d.to.Local())
		} else {
			q = q.Where(column+" <= ?", d.to.Local())
		}
	}
	return q
}
