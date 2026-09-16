package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	attemptCount       = 3
	criterionCount     = 5
	attackTreeMaxNodes = 64

	controlBypassed      = "bypassed"
	controlHeld          = "held"
	controlNotApplicable = "not_applicable"
	controlUnresolved    = "unresolved"
	controlNotAttempted  = "not_attempted"
)

// ErrMissingRubric identifies reports produced by the pre-rubric verify skill.
// Stored-row readers use it to keep historical verification records visible as
// ungraded; live verify ingestion requires the current report shape.
var ErrMissingRubric = errors.New("verify report has no grading rubric")

// Report is the structured output of the verify skill.
type Report struct {
	Status                string                 `json:"status"`
	Preflight             *Preflight             `json:"preflight,omitempty"`
	AttackTree            *AttackTree            `json:"attack_tree,omitempty"`
	SeverityPrerequisites *SeverityPrerequisites `json:"severity_prerequisites,omitempty"`
	Attempts              []Attempt              `json:"attempts"`
	Criteria              *Criteria              `json:"criteria,omitempty"`
	Reproducer            string                 `json:"reproducer,omitempty"`
	Evidence              string                 `json:"evidence,omitempty"`
	Notes                 string                 `json:"notes,omitempty"`
}

// Preflight records whether the supplied reproduction is safe to execute in
// the isolated workspace.
type Preflight struct {
	Classification string `json:"classification"`
	Justification  string `json:"justification"`
}

// AttackTree records the concrete preconditions and code path that support or
// block the claimed security effect. It is optional here so verification rows
// written before attack trees were introduced remain readable; schema.json
// requires it for newly generated reports.
type AttackTree struct {
	Goal     string           `json:"goal"`
	RootID   string           `json:"root_id"`
	Verdict  string           `json:"verdict"`
	Nodes    []AttackTreeNode `json:"nodes"`
	Blockers []string         `json:"blockers"`
}

// AttackTreeNode is one evidenced condition in the attack tree. ParentID is
// nil only for the root goal; every other node must name another node.
type AttackTreeNode struct {
	ID          string  `json:"id"`
	ParentID    *string `json:"parent_id"`
	Kind        string  `json:"kind"`
	Description string  `json:"description"`
	Status      string  `json:"status"`
	Evidence    string  `json:"evidence"`
}

// SeverityPrerequisites records the evidence-backed inputs used by the host's
// deterministic severity-cap rules. It is optional in the Go model so stored
// verification reports written before the contract was introduced remain
// readable; schema.json and live ingestion require it for new reports.
type SeverityPrerequisites struct {
	AttackerPosition   PrerequisiteValue `json:"attacker_position"`
	UserInteraction    PrerequisiteValue `json:"user_interaction"`
	OutcomeDeterminism PrerequisiteValue `json:"outcome_determinism"`
	Impact             PrerequisiteValue `json:"impact"`
	ExistingCapability PrerequisiteValue `json:"existing_capability"`
}

// PrerequisiteValue pairs one closed classification with the concrete source
// or runtime evidence that supports it. Unknown and not_attempted still require
// evidence naming the proof gap or the reason evaluation could not start.
type PrerequisiteValue struct {
	Value    string `json:"value"`
	Evidence string `json:"evidence"`
}

// NamedPrerequisite supplies stable display labels for verification history.
type NamedPrerequisite struct {
	Name       string
	Assessment PrerequisiteValue
}

// List returns the fixed prerequisite rows in report order.
func (p SeverityPrerequisites) List() []NamedPrerequisite {
	return []NamedPrerequisite{
		{Name: "Attacker position", Assessment: p.AttackerPosition},
		{Name: "User interaction", Assessment: p.UserInteraction},
		{Name: "Outcome determinism", Assessment: p.OutcomeDeterminism},
		{Name: "Impact", Assessment: p.Impact},
		{Name: "Existing capability", Assessment: p.ExistingCapability},
	}
}

// Attempt records one of the three independent reproduction attempts.
type Attempt struct {
	Number       int    `json:"number"`
	Outcome      string `json:"outcome"`
	Evidence     string `json:"evidence"`
	FailureClass string `json:"failure_class"`
	CrashSite    string `json:"crash_site"`
}

// Criterion records how one rubric row was judged, including facts that
// weaken the conclusion or could not be established.
type Criterion struct {
	Verdict         string `json:"verdict"`
	Method          string `json:"method"`
	Evidence        string `json:"evidence"`
	Counterevidence string `json:"counterevidence"`
	ProofGap        string `json:"proof_gap"`
	Confidence      string `json:"confidence"`
}

// Criteria keeps the five scored properties fixed-shape. ControlBypass is a
// non-scored gate and is optional only so historical rows remain readable.
type Criteria struct {
	PoCWellFormed                   Criterion      `json:"poc_well_formed"`
	ReproducesThreeOfThree          Criterion      `json:"reproduces_three_of_three"`
	ClaimedFailureClass             Criterion      `json:"claimed_failure_class"`
	PublicInterfaceToFirstPartySink Criterion      `json:"public_interface_to_first_party_sink"`
	Deterministic                   Criterion      `json:"deterministic"`
	ControlBypass                   *ControlBypass `json:"control_bypass,omitempty"`
}

// ControlBypass is a non-scored verification gate over the design controls
// that the host matched to the finding. It is optional in the Go model so
// verification rows created before this field existed remain readable;
// schema.json requires it for newly generated reports.
type ControlBypass struct {
	MatchedControls   []string            `json:"matched_controls"`
	Assessments       []ControlAssessment `json:"assessments"`
	UnavailableReason string              `json:"unavailable_reason,omitempty"`
}

// ControlAssessment records what happened to one matched design control.
// Evidence is required for every disposition, including why a control does
// not apply or why its state could not be established.
type ControlAssessment struct {
	ControlID   string `json:"control_id"`
	Disposition string `json:"disposition"`
	Evidence    string `json:"evidence"`
}

// NamedCriterion supplies stable display labels without making the report
// schema an open-ended map.
type NamedCriterion struct {
	Name      string
	Criterion Criterion
}

// Parse decodes and validates one rubric report.
func Parse(raw string) (Report, error) {
	var report Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return Report{}, fmt.Errorf("decode verification report: %w", err)
	}
	if report.Criteria == nil {
		return Report{}, ErrMissingRubric
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// Validate enforces relationships that JSON Schema cannot express. Structural
// and most status-consistency rules live in schema.json.
func (r Report) Validate() error {
	if r.Criteria == nil {
		return ErrMissingRubric
	}
	seen := make(map[int]bool, attemptCount)
	for i, attempt := range r.Attempts {
		if seen[attempt.Number] {
			return fmt.Errorf("attempts[%d].number %d is not unique in 1..%d", i, attempt.Number, attemptCount)
		}
		seen[attempt.Number] = true
	}
	if r.AttackTree != nil {
		if err := r.validateAttackTree(); err != nil {
			return err
		}
	}
	if err := r.validateControlBypass(); err != nil {
		return err
	}
	return r.validateSeverityPrerequisites()
}

func (r Report) validateSeverityPrerequisites() error {
	assessment := r.SeverityPrerequisites
	if assessment == nil {
		return nil
	}
	fields := []struct {
		name    string
		value   PrerequisiteValue
		allowed map[string]bool
	}{
		{"attacker_position", assessment.AttackerPosition, map[string]bool{
			"remote_unauthenticated": true, "remote_authenticated": true,
			"internal_authenticated": true, "local": true, "host_shell": true,
			"long_term_physical": true, "unknown": true, controlNotAttempted: true,
		}},
		{"user_interaction", assessment.UserInteraction, map[string]bool{
			"none": true, "required": true, "unknown": true, controlNotAttempted: true,
		}},
		{"outcome_determinism", assessment.OutcomeDeterminism, map[string]bool{
			"deterministic": true, "probabilistic_llm": true, "unknown": true, controlNotAttempted: true,
		}},
		{"impact", assessment.Impact, map[string]bool{
			"code_execution_or_equivalent": true, "privilege_escalation": true,
			"sensitive_data_access": true, "availability": true, "other": true,
			"unknown": true, controlNotAttempted: true,
		}},
		{"existing_capability", assessment.ExistingCapability, map[string]bool{
			"none": true, "less_than_outcome": true, "support_channel_equivalent": true,
			"equivalent_or_greater": true, "unknown": true, controlNotAttempted: true,
		}},
	}
	notAttemptedStatus := r.Status == "deferred" || r.Status == controlNotAttempted
	for _, field := range fields {
		if !field.allowed[field.value.Value] {
			return fmt.Errorf("severity_prerequisites.%s.value %q is invalid", field.name, field.value.Value)
		}
		if strings.TrimSpace(field.value.Evidence) == "" {
			return fmt.Errorf("severity_prerequisites.%s.evidence is empty", field.name)
		}
		if notAttemptedStatus && field.value.Value != controlNotAttempted {
			return fmt.Errorf("verify status %s requires severity_prerequisites.%s.value not_attempted", r.Status, field.name)
		}
		if !notAttemptedStatus && field.value.Value == controlNotAttempted {
			return fmt.Errorf("verify status %s does not permit severity_prerequisites.%s.value not_attempted", r.Status, field.name)
		}
	}
	return nil
}

func (r Report) validateControlBypass() error {
	gate := r.Criteria.ControlBypass
	if gate == nil {
		return nil
	}
	if err := gate.validate(); err != nil {
		return err
	}
	return validateControlBypassStatus(r.Status, gate.Assessments)
}

func (gate ControlBypass) validate() error {
	if gate.UnavailableReason != "" {
		if strings.TrimSpace(gate.UnavailableReason) == "" {
			return errors.New("criteria.control_bypass.unavailable_reason is empty")
		}
		if len(gate.MatchedControls) != 0 || len(gate.Assessments) != 0 {
			return errors.New("criteria.control_bypass with unavailable_reason requires empty matched_controls and assessments")
		}
	}
	matched := make(map[string]struct{}, len(gate.MatchedControls))
	for i, id := range gate.MatchedControls {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("criteria.control_bypass.matched_controls[%d] is empty", i)
		}
		if _, exists := matched[id]; exists {
			return fmt.Errorf("criteria.control_bypass.matched_controls[%d] %q is not unique", i, id)
		}
		matched[id] = struct{}{}
	}

	assessed := make(map[string]struct{}, len(gate.Assessments))
	for i, assessment := range gate.Assessments {
		if strings.TrimSpace(assessment.ControlID) == "" {
			return fmt.Errorf("criteria.control_bypass.assessments[%d].control_id is empty", i)
		}
		if strings.TrimSpace(assessment.Evidence) == "" {
			return fmt.Errorf("criteria.control_bypass.assessments[%d].evidence is empty", i)
		}
		if _, exists := matched[assessment.ControlID]; !exists {
			return fmt.Errorf("criteria.control_bypass.assessments[%d] names unmatched control %q", i, assessment.ControlID)
		}
		if _, exists := assessed[assessment.ControlID]; exists {
			return fmt.Errorf("criteria.control_bypass.assessments[%d] repeats control %q", i, assessment.ControlID)
		}
		assessed[assessment.ControlID] = struct{}{}
		if !controlDispositionValid(assessment.Disposition) {
			return fmt.Errorf("criteria.control_bypass.assessments[%d].disposition %q is invalid", i, assessment.Disposition)
		}
	}
	for _, id := range gate.MatchedControls {
		if _, exists := assessed[id]; !exists {
			return fmt.Errorf("criteria.control_bypass has no assessment for matched control %q", id)
		}
	}

	return nil
}

func validateControlBypassStatus(status string, assessments []ControlAssessment) error {
	for _, assessment := range assessments {
		switch status {
		case "confirmed":
			if assessment.Disposition != controlBypassed && assessment.Disposition != controlNotApplicable {
				return fmt.Errorf("verify status confirmed requires control %q to be bypassed or not_applicable, got %q", assessment.ControlID, assessment.Disposition)
			}
		case "fixed":
			if assessment.Disposition == controlUnresolved || assessment.Disposition == controlNotAttempted {
				return fmt.Errorf("verify status fixed requires a resolved assessment for control %q, got %q", assessment.ControlID, assessment.Disposition)
			}
		case "deferred", "not_attempted":
			if assessment.Disposition != controlNotAttempted {
				return fmt.Errorf("verify status %s requires control %q to be not_attempted, got %q", status, assessment.ControlID, assessment.Disposition)
			}
		}
	}
	return nil
}

func controlDispositionValid(disposition string) bool {
	switch disposition {
	case controlBypassed, controlHeld, controlNotApplicable, controlUnresolved, controlNotAttempted:
		return true
	default:
		return false
	}
}

// ValidateControlContext proves that the model accounted for exactly the
// controls, or the resolution failure, that the host staged for this finding.
// JSON Schema cannot compare report contents with context.json, so live
// ingestion calls this after ordinary validation.
func (r Report) ValidateControlContext(expected []string, unavailableReason string) error {
	if r.Criteria == nil || r.Criteria.ControlBypass == nil {
		return errors.New("verify report requires criteria.control_bypass")
	}
	if got := r.Criteria.ControlBypass.UnavailableReason; got != unavailableReason {
		return fmt.Errorf("criteria.control_bypass.unavailable_reason %q does not match host-resolved reason %q", got, unavailableReason)
	}
	want := slices.Clone(expected)
	got := slices.Clone(r.Criteria.ControlBypass.MatchedControls)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return fmt.Errorf("criteria.control_bypass.matched_controls %v do not match host-resolved controls %v", got, want)
	}
	return nil
}

func (r Report) validateAttackTree() error {
	tree := r.AttackTree
	if len(tree.Nodes) == 0 {
		return errors.New("attack_tree.nodes is empty")
	}
	if len(tree.Nodes) > attackTreeMaxNodes {
		return fmt.Errorf("attack_tree.nodes has %d entries; maximum is %d", len(tree.Nodes), attackTreeMaxNodes)
	}
	nodes := make(map[string]AttackTreeNode, len(tree.Nodes))
	pathState := make(map[string]uint8, len(tree.Nodes))
	for i, node := range tree.Nodes {
		if _, exists := nodes[node.ID]; exists {
			return fmt.Errorf("attack_tree.nodes[%d].id %q is not unique", i, node.ID)
		}
		nodes[node.ID] = node
	}
	root, ok := nodes[tree.RootID]
	if !ok {
		return fmt.Errorf("attack_tree.root_id %q does not identify a node", tree.RootID)
	}
	if root.ParentID != nil {
		return fmt.Errorf("attack_tree root %q must have null parent_id", tree.RootID)
	}
	if root.Kind != "goal" {
		return fmt.Errorf("attack_tree root %q must have kind goal", tree.RootID)
	}
	for i, node := range tree.Nodes {
		if node.ID == tree.RootID {
			continue
		}
		if node.Kind == "goal" {
			return fmt.Errorf("attack_tree.nodes[%d] %q has kind goal but is not the root", i, node.ID)
		}
		if node.ParentID == nil {
			return fmt.Errorf("attack_tree.nodes[%d] %q has null parent_id but is not the root", i, node.ID)
		}
		if err := validateAttackTreePath(node.ID, tree.RootID, nodes, pathState); err != nil {
			return err
		}
	}
	if err := validateAttackTreeVerdict(r.Status, tree.Verdict); err != nil {
		return err
	}
	wantRootStatus := map[string]string{
		"reachable":     "satisfied",
		"blocked":       "blocked",
		"unproven":      "unproven",
		"not_attempted": "not_attempted",
	}[tree.Verdict]
	if wantRootStatus != "" && root.Status != wantRootStatus {
		return fmt.Errorf("attack_tree root status %q does not match verdict %q", root.Status, tree.Verdict)
	}
	return validateAttackTreeNodeStatuses(*tree)
}

func validateAttackTreeNodeStatuses(tree AttackTree) error {
	hasVerdictNode := false
	for _, node := range tree.Nodes {
		switch tree.Verdict {
		case "reachable":
			if node.Status != "satisfied" {
				return fmt.Errorf("attack_tree verdict reachable requires node %q to be satisfied", node.ID)
			}
		case "blocked":
			hasVerdictNode = hasVerdictNode || node.Status == "blocked"
		case "unproven":
			hasVerdictNode = hasVerdictNode || node.Status == "unproven"
		case "not_attempted":
			if node.Status != "not_attempted" {
				return fmt.Errorf("attack_tree verdict not_attempted requires node %q to be not_attempted", node.ID)
			}
		}
	}
	if tree.Verdict == "reachable" && len(tree.Blockers) != 0 {
		return errors.New("attack_tree verdict reachable requires an empty blockers list")
	}
	if tree.Verdict == "reachable" {
		if !attackTreeHasKind(tree.Nodes, "entry_point") {
			return errors.New("attack_tree verdict reachable requires an entry_point node")
		}
		if !attackTreeHasKind(tree.Nodes, "sink") {
			return errors.New("attack_tree verdict reachable requires a sink node")
		}
	}
	if tree.Verdict == "blocked" {
		if !hasVerdictNode {
			return errors.New("attack_tree verdict blocked requires at least one blocked node")
		}
		if len(tree.Blockers) == 0 {
			return errors.New("attack_tree verdict blocked requires at least one blocker")
		}
	}
	if tree.Verdict == "unproven" && !hasVerdictNode {
		return errors.New("attack_tree verdict unproven requires at least one unproven node")
	}
	return nil
}

func attackTreeHasKind(nodes []AttackTreeNode, kind string) bool {
	for _, node := range nodes {
		if node.Kind == kind {
			return true
		}
	}
	return false
}

func validateAttackTreePath(id, rootID string, nodes map[string]AttackTreeNode, state map[string]uint8) error {
	const (
		attackTreeVisiting  = 1
		attackTreeValidated = 2
	)
	if id == rootID {
		state[id] = attackTreeValidated
		return nil
	}
	switch state[id] {
	case attackTreeVisiting:
		return fmt.Errorf("attack_tree contains a parent cycle at node %q", id)
	case attackTreeValidated:
		return nil
	}
	state[id] = attackTreeVisiting
	node := nodes[id]
	if node.ParentID == nil {
		return fmt.Errorf("attack_tree node %q is disconnected from root %q", id, rootID)
	}
	parentID := *node.ParentID
	if _, ok := nodes[parentID]; !ok {
		return fmt.Errorf("attack_tree node %q names missing parent %q", id, parentID)
	}
	if err := validateAttackTreePath(parentID, rootID, nodes, state); err != nil {
		return err
	}
	state[id] = attackTreeValidated
	return nil
}

func validateAttackTreeVerdict(status, verdict string) error {
	want := ""
	switch status {
	case "confirmed":
		want = "reachable"
	case "fixed":
		want = "blocked"
	case "deferred", "not_attempted":
		want = "not_attempted"
	case "inconclusive":
		if verdict != "blocked" && verdict != "unproven" {
			return fmt.Errorf("verify status \"inconclusive\" requires attack_tree.verdict \"blocked\" or \"unproven\", got %q", verdict)
		}
	}
	if want != "" && verdict != want {
		return fmt.Errorf("verify status %q requires attack_tree.verdict %q, got %q", status, want, verdict)
	}
	return nil
}

// Score is the fraction of the five fixed criteria that passed.
func (r Report) Score() float64 {
	passed := 0
	for _, named := range r.Criteria.List() {
		if named.Criterion.Verdict == "pass" {
			passed++
		}
	}
	return float64(passed) / criterionCount
}

// List returns the fixed rubric in display order.
func (c Criteria) List() []NamedCriterion {
	return []NamedCriterion{
		{Name: "PoC well formed", Criterion: c.PoCWellFormed},
		{Name: "Reproduces 3/3", Criterion: c.ReproducesThreeOfThree},
		{Name: "Claimed failure class", Criterion: c.ClaimedFailureClass},
		{Name: "Public interface to first-party sink", Criterion: c.PublicInterfaceToFirstPartySink},
		{Name: "Deterministic", Criterion: c.Deterministic},
	}
}
