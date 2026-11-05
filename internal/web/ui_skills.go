package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

// Skills (02 #85-#88, F-SKILL-01..03). Create and PATCH run the same rules
// as the HTML form (validateSkillForm) but report them per field, and also
// reject what the form silently normalised away (an unknown model, negative
// max_turns). PATCH is field-level autosave: a body equal to the stored row
// is a no-op that leaves version and updated_at alone; any real change bumps
// version as skillUpdate does. Both publish meta {changed:["skills"]}.

const (
	uiSkillNameMax        = 64
	uiSkillDescriptionMax = 1024
	uiSkillMetaChanged    = "skills"
	uiSkillDescKey        = "description"
	uiSkillOutputFileKey  = "output_file"
	uiSkillOutputKindKey  = "output_kind"
	uiSkillMaxTurnsKey    = "max_turns"
	uiSkillSchemaKey      = "schema_json"
)

var errSkillChanged = errors.New("skill changed since you loaded it")

// uiSkillFields is the writable part of a skill; nil means "not sent".
type uiSkillFields struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Body        *string `json:"body"`
	OutputFile  *string `json:"output_file"`
	OutputKind  *string `json:"output_kind"`
	MaxTurns    *int    `json:"max_turns"`
	Model       *string `json:"model"`
	SchemaJSON  *string `json:"schema_json"`
}

// uiSkillPatchBody adds the active toggle, which create does not take (a new
// skill is always active, as on the HTML form).
type uiSkillPatchBody struct {
	uiSkillFields
	Active *bool `json:"active"`
}

func setTrimmed(dst *string, v *string) {
	if v != nil {
		*dst = strings.TrimSpace(*v)
	}
}

// overlay writes the sent fields onto form with readSkillForm's trimming
// (body is kept verbatim, as there).
func (b uiSkillFields) overlay(form *skillFormValues) {
	setTrimmed(&form.Name, b.Name)
	setTrimmed(&form.Description, b.Description)
	if b.Body != nil {
		form.Body = *b.Body
	}
	setTrimmed(&form.OutputFile, b.OutputFile)
	setTrimmed(&form.OutputKind, b.OutputKind)
	if b.MaxTurns != nil {
		form.MaxTurns = *b.MaxTurns
	}
	setTrimmed(&form.Model, b.Model)
	setTrimmed(&form.SchemaJSON, b.SchemaJSON)
}

// skillFormFrom is the form a stored skill would round-trip through.
func skillFormFrom(sk db.Skill) skillFormValues {
	return skillFormValues{
		Name: sk.Name, Description: sk.Description, Body: sk.Body, OutputFile: sk.OutputFile,
		OutputKind: sk.OutputKind, MaxTurns: sk.MaxTurns, Model: sk.Model, SchemaJSON: sk.SchemaJSON,
		Active: sk.Active,
	}
}

// validateSkillFields is validateSkillForm reported per field, plus the
// length limits and the checks the form side-stepped by normalising.
func validateSkillFields(form skillFormValues) uiFieldErrors {
	errs := uiFieldErrors{}
	switch {
	case form.Name == "":
		errs[uiKeyName] = "required"
	case len(form.Name) > uiSkillNameMax:
		errs[uiKeyName] = "must be at most " + strconv.Itoa(uiSkillNameMax) + " characters"
	case !validateSkillName(form.Name):
		errs[uiKeyName] = "must be lowercase alphanumeric with hyphens (e.g. my-skill-1)"
	}
	switch {
	case form.Description == "":
		errs[uiSkillDescKey] = "required"
	case len(form.Description) > uiSkillDescriptionMax:
		errs[uiSkillDescKey] = "must be at most " + strconv.Itoa(uiSkillDescriptionMax) + " characters"
	}
	if !validateOutputFile(form.OutputFile) {
		errs[uiSkillOutputFileKey] = "must be a plain filename with no path separators"
	}
	if !skills.OutputKinds[form.OutputKind] {
		errs[uiSkillOutputKindKey] = "is not a recognised parser"
	}
	if form.MaxTurns < 0 {
		errs[uiSkillMaxTurnsKey] = "must be 0 (use the default) or more"
	}
	if form.Model != "" && !ValidModelPreference(form.Model) {
		errs[uiKeyModel] = "must be a configured model id or a model tier"
	}
	if form.SchemaJSON != "" && !json.Valid([]byte(form.SchemaJSON)) {
		errs[uiSkillSchemaKey] = "must be valid JSON"
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// skillNameTaken reports whether another skill already uses name.
func (s *Server) skillNameTaken(name string, exceptID uint) bool {
	var n int64
	s.DB.Model(&db.Skill{}).Where("name = ? AND id <> ?", name, exceptID).Count(&n)
	return n > 0
}

// uiSkillDetail is the UISkillDetail projection: the row plus the two blobs.
func uiSkillDetail(sk db.Skill) map[string]any {
	m := uiSkillRow(sk)
	m["body"] = sk.Body
	m[uiSkillSchemaKey] = sk.SchemaJSON
	return m
}

func writeUISkill(w http.ResponseWriter, status int, sk db.Skill) {
	setETag(w, sk.UpdatedAt)
	writeUIJSON(w, status, uiSkillDetail(sk))
}

func (s *Server) uiSkillsList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Omit("body", "schema_json", "metadata").Order("active desc, name asc")
	if v := r.URL.Query().Get("active"); v != "" {
		active, err := strconv.ParseBool(v)
		if err != nil {
			uiBadParam(w, `active must be true or false, got "`+v+`"`)
			return
		}
		q = q.Where("active = ?", active)
	}
	var rows []db.Skill
	if err := q.Find(&rows).Error; err != nil {
		uiInternal(w, err)
		return
	}
	out := make([]map[string]any, len(rows))
	for i, sk := range rows {
		out[i] = uiSkillRow(sk)
	}
	writeUIJSON(w, http.StatusOK, out)
}

func (s *Server) uiSkillShow(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var sk db.Skill
	if err := s.DB.First(&sk, id).Error; err != nil {
		uiDBError(w, err, "skill")
		return
	}
	writeUISkill(w, http.StatusOK, sk)
}

func (s *Server) uiSkillCreate(w http.ResponseWriter, r *http.Request) {
	var body uiSkillFields
	if !decodeInsightBody(w, r, &body) {
		return
	}
	form := skillFormValues{Active: true}
	body.overlay(&form)
	if errs := validateSkillFields(form); errs != nil {
		writeUIFields(w, errs)
		return
	}
	if s.skillNameTaken(form.Name, 0) {
		writeUIFields(w, uiFieldErrors{uiKeyName: "a skill with this name already exists"})
		return
	}
	sk, err := s.createSkill(form)
	if err != nil {
		uiInternal(w, err)
		return
	}
	s.publishMeta(uiSkillMetaChanged)
	writeUISkill(w, http.StatusCreated, sk)
}

func (s *Server) uiSkillPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := uiPathID(w, r, "id")
	if !ok {
		return
	}
	var sk db.Skill
	if err := s.DB.First(&sk, id).Error; err != nil {
		uiDBError(w, err, "skill")
		return
	}
	var body uiSkillPatchBody
	if !decodeInsightBody(w, r, &body) {
		return
	}
	if !checkIfMatch(w, r, sk.UpdatedAt, uiSkillDetail(sk)) {
		return
	}
	form := skillFormFrom(sk)
	body.overlay(&form)
	if body.Active != nil {
		form.Active = *body.Active
	}
	if errs := validateSkillFields(form); errs != nil {
		writeUIFields(w, errs)
		return
	}
	if form == skillFormFrom(sk) {
		writeUISkill(w, http.StatusOK, sk)
		return
	}
	if form.Name != sk.Name && s.skillNameTaken(form.Name, sk.ID) {
		writeUIFields(w, uiFieldErrors{uiKeyName: "a skill with this name already exists"})
		return
	}
	saved, err := s.saveSkillIfUnchanged(sk, form)
	if errors.Is(err, errSkillChanged) {
		writeUIErrorExtra(w, http.StatusConflict, uiCodeConflict, err.Error(), map[string]any{"current": uiSkillDetail(saved)})
		return
	}
	if err != nil {
		uiDBError(w, err, "skill")
		return
	}
	s.publishMeta(uiSkillMetaChanged)
	writeUISkill(w, http.StatusOK, saved)
}

// saveSkillIfUnchanged applies form to the skill and bumps its version, but
// only if the row still carries the updated_at it was loaded with. On
// errSkillChanged the returned skill is the current stored row.
func (s *Server) saveSkillIfUnchanged(loaded db.Skill, form skillFormValues) (db.Skill, error) {
	var out db.Skill
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&out, loaded.ID).Error; err != nil {
			return err
		}
		if !sameVersion(out.UpdatedAt, loaded.UpdatedAt) {
			return errSkillChanged
		}
		form.apply(&out)
		out.Version++
		return tx.Save(&out).Error
	})
	return out, err
}
