package web

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Label catalogue management (#22a). Finding label assignment (PUT
// /ui/findings/{id}/labels) already creates unknown names through
// db.SetFindingLabels' FirstOrCreate; these routes add colour, rename and
// delete. Every change publishes `meta {changed:["labels"]}` so the SPA
// refetches /ui/meta/dynamic.

const uiLabelJoinTable = "finding_labels_join"

var uiLabelColorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// uiLabelRow is LabelRow: Label plus how many findings carry it.
func uiLabelRow(l db.FindingLabel, findingCount int64) map[string]any {
	m := uiLabel(l)
	m["finding_count"] = findingCount
	return m
}

func (s *Server) uiLabelFindingCount(id uint) int64 {
	var n int64
	s.DB.Table(uiLabelJoinTable).Where("finding_label_id = ?", id).Count(&n)
	return n
}

func (s *Server) uiLabelList(w http.ResponseWriter, r *http.Request) {
	var labels []db.FindingLabel
	if err := s.DB.WithContext(r.Context()).Order(uiKeyName).Find(&labels).Error; err != nil {
		uiInternal(w, err)
		return
	}
	var counts []struct {
		FindingLabelID uint
		N              int64
	}
	if err := s.DB.Table(uiLabelJoinTable).Select("finding_label_id, COUNT(*) AS n").
		Group("finding_label_id").Scan(&counts).Error; err != nil {
		uiInternal(w, err)
		return
	}
	byID := make(map[uint]int64, len(counts))
	for _, c := range counts {
		byID[c.FindingLabelID] = c.N
	}
	out := make([]map[string]any, len(labels))
	for i, l := range labels {
		out[i] = uiLabelRow(l, byID[l.ID])
	}
	writeUIJSON(w, http.StatusOK, out)
}

type uiLabelBody struct {
	Name  *string `json:"name"`
	Color *string `json:"color"`
}

// validate checks the provided fields; requireName is set on create.
func (b uiLabelBody) validate(requireName bool) error {
	errs := uiFieldErrors{}
	if b.Name != nil || requireName {
		name := ""
		if b.Name != nil {
			name = strings.TrimSpace(*b.Name)
		}
		switch {
		case name == "":
			errs[uiKeyName] = "name is required"
		case utf8.RuneCountInString(name) > uiLabelNameMax:
			errs[uiKeyName] = "name must be at most 64 characters"
		}
	}
	if b.Color != nil && *b.Color != "" && !uiLabelColorRE.MatchString(*b.Color) {
		errs["color"] = "color must be #rrggbb"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// uiLabelNameTaken reports whether another label already has name.
func (s *Server) uiLabelNameTaken(name string, except uint) bool {
	var n int64
	s.DB.Model(&db.FindingLabel{}).Where("name = ? AND id <> ?", name, except).Count(&n)
	return n > 0
}

func writeUILabelNameConflict(w http.ResponseWriter, name string) {
	writeUIError(w, http.StatusConflict, uiCodeConflict, "a label named "+name+" already exists",
		map[string]string{uiKeyName: "already exists"})
}

func (s *Server) uiLabelCreate(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeUIFindingBody[uiLabelBody](w, r)
	if !ok {
		return
	}
	if err := body.validate(true); err != nil {
		writeUIFields(w, err)
		return
	}
	label := db.FindingLabel{Name: strings.TrimSpace(*body.Name)}
	if body.Color != nil {
		label.Color = *body.Color
	}
	if s.uiLabelNameTaken(label.Name, 0) {
		writeUILabelNameConflict(w, label.Name)
		return
	}
	if err := s.DB.WithContext(r.Context()).Create(&label).Error; err != nil {
		uiInternal(w, err)
		return
	}
	s.publishMeta(uiEventLabels)
	writeUIJSON(w, http.StatusCreated, uiLabelRow(label, 0))
}

// loadUILabel parses {id} and loads the label.
func (s *Server) loadUILabel(w http.ResponseWriter, r *http.Request) (db.FindingLabel, bool) {
	var label db.FindingLabel
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return label, false
	}
	if err := s.DB.WithContext(r.Context()).First(&label, id).Error; err != nil {
		uiDBError(w, err, "label")
		return label, false
	}
	return label, true
}

func (s *Server) uiLabelPatch(w http.ResponseWriter, r *http.Request) {
	label, ok := s.loadUILabel(w, r)
	if !ok {
		return
	}
	body, ok := decodeUIFindingBody[uiLabelBody](w, r)
	if !ok {
		return
	}
	if err := body.validate(false); err != nil {
		writeUIFields(w, err)
		return
	}
	updates := map[string]any{}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if s.uiLabelNameTaken(name, label.ID) {
			writeUILabelNameConflict(w, name)
			return
		}
		updates[uiKeyName] = name
	}
	if body.Color != nil {
		updates["color"] = *body.Color
	}
	if len(updates) > 0 {
		if err := s.DB.WithContext(r.Context()).Model(&label).Updates(updates).Error; err != nil {
			uiInternal(w, err)
			return
		}
		s.publishMeta(uiEventLabels)
	}
	writeUIJSON(w, http.StatusOK, uiLabelRow(label, s.uiLabelFindingCount(label.ID)))
}

func (s *Server) uiLabelDelete(w http.ResponseWriter, r *http.Request) {
	label, ok := s.loadUILabel(w, r)
	if !ok {
		return
	}
	err := s.DB.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM "+uiLabelJoinTable+" WHERE finding_label_id = ?", label.ID).Error; err != nil {
			return err
		}
		res := tx.Delete(&db.FindingLabel{}, label.ID)
		if res.Error == nil && res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return res.Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		uiNotFound(w, "label")
		return
	}
	if err != nil {
		uiInternal(w, err)
		return
	}
	s.publishMeta(uiEventLabels)
	w.Header().Set(cacheControlHeader, noStore)
	w.WriteHeader(http.StatusNoContent)
}
