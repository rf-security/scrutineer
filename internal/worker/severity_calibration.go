package worker

import (
	"fmt"
	"slices"

	"scrutineer/internal/db"
	"scrutineer/internal/threatmodel"
	"scrutineer/internal/verification"
)

const controlSeverityCap = "Medium"

// findingSeverityCalibration is the host-derived projection produced from a
// reconciled control-bypass gate. Evaluated distinguishes an authoritative
// no-cap result from an ungraded report that must leave the prior projection
// untouched.
type findingSeverityCalibration struct {
	Maximum    string
	Caps       []string
	Incomplete bool
	Evaluated  bool
}

func calibrateControlSeverity(
	controls *skillContextControls,
	gate *verification.ControlBypass,
) findingSeverityCalibration {
	result := findingSeverityCalibration{Evaluated: true}
	if controls == nil {
		return result
	}
	if gate == nil || controls.UnavailableWhy != "" || gate.UnavailableReason != "" {
		result.Incomplete = true
		return result
	}

	controlsByID := make(map[string]threatmodel.Control, len(controls.Matched))
	for _, control := range controls.Matched {
		controlsByID[control.ID] = control
	}
	for _, assessment := range gate.Assessments {
		switch assessment.Disposition {
		case "bypassed", "not_applicable":
			continue
		case "unresolved", "not_attempted":
			result.Incomplete = true
			continue
		case "held":
		default:
			result.Incomplete = true
			continue
		}

		control, ok := controlsByID[assessment.ControlID]
		if !ok {
			result.Incomplete = true
			continue
		}
		var reason string
		switch control.Kind {
		case threatmodel.KindAuthorization:
			reason = fmt.Sprintf("authorization control %q held; severity capped at %s", control.ID, controlSeverityCap)
		case threatmodel.KindSandbox:
			reason = fmt.Sprintf("sandbox control %q held; severity capped at %s", control.ID, controlSeverityCap)
		default:
			continue
		}
		result.Caps = append(result.Caps, reason)
		result.Maximum = controlSeverityCap
	}

	slices.Sort(result.Caps)
	return result
}

func calibrateFindingSeverity(
	controls *skillContextControls,
	gate *verification.ControlBypass,
	prerequisites *verification.SeverityPrerequisites,
) findingSeverityCalibration {
	control := calibrateControlSeverity(controls, gate)
	prerequisite := calibratePrerequisiteSeverity(prerequisites)
	result := findingSeverityCalibration{
		Maximum:    stricterSeverityMaximum(control.Maximum, prerequisite.Maximum),
		Caps:       append(control.Caps, prerequisite.Caps...),
		Incomplete: control.Incomplete || prerequisite.Incomplete,
		Evaluated:  control.Evaluated && prerequisite.Evaluated,
	}
	slices.Sort(result.Caps)
	return result
}

func calibratePrerequisiteSeverity(
	prerequisites *verification.SeverityPrerequisites,
) findingSeverityCalibration {
	result := findingSeverityCalibration{Evaluated: true}
	if prerequisites == nil {
		result.Incomplete = true
		return result
	}

	values := prerequisites.List()
	for _, value := range values {
		if value.Assessment.Value == "unknown" || value.Assessment.Value == "not_attempted" {
			result.Incomplete = true
		}
	}

	addCap := func(maximum, reason string) {
		result.Maximum = stricterSeverityMaximum(result.Maximum, maximum)
		result.Caps = append(result.Caps, reason)
	}

	attackerPositionCapped := false
	switch prerequisites.AttackerPosition.Value {
	case "host_shell":
		addCap("Low", "attacker already requires a host shell; severity forced to Low")
		attackerPositionCapped = true
	case "long_term_physical":
		addCap("Low", "attacker already requires long-term physical access; severity forced to Low")
		attackerPositionCapped = true
	case "local":
		addCap("Medium", "attack vector is local-only; severity capped at Medium")
		attackerPositionCapped = true
	}
	if prerequisites.ExistingCapability.Value == "equivalent_or_greater" {
		addCap("Low", "attacker already has a capability equivalent to or greater than the claimed outcome; severity forced to Low")
	}
	if prerequisites.AttackerPosition.Value == "internal_authenticated" &&
		prerequisites.ExistingCapability.Value == "support_channel_equivalent" {
		addCap("Medium", "authenticated internal attacker already has an equivalent support channel; severity capped at Medium")
		attackerPositionCapped = true
	}
	if prerequisites.OutcomeDeterminism.Value == "probabilistic_llm" {
		addCap("High", "outcome depends on probabilistic LLM behavior; severity capped at High")
	}

	// Critical is reserved for unauthenticated, no-interaction remote code
	// execution or an equivalent effect. A known contrary input caps it at High;
	// unknown inputs only mark calibration incomplete above.
	if !attackerPositionCapped && knownAndNot(prerequisites.AttackerPosition.Value, "remote_unauthenticated") {
		addCap("High", "attacker position is not remote unauthenticated; Critical requires an unauthenticated remote attacker")
	}
	if prerequisites.UserInteraction.Value == "required" {
		addCap("High", "attack requires user interaction; Critical requires no user interaction")
	}
	if knownAndNot(prerequisites.Impact.Value, "code_execution_or_equivalent") {
		addCap("High", "impact is not code execution or equivalent; Critical requires code execution or an equivalent effect")
	}

	slices.Sort(result.Caps)
	return result
}

func knownAndNot(value, required string) bool {
	return value != required && value != "unknown" && value != "not_attempted"
}

func stricterSeverityMaximum(a, b string) string {
	if b == "" {
		return a
	}
	if a == "" || db.SeverityAtLeast(a, b) {
		return b
	}
	return a
}
