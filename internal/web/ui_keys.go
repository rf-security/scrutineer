package web

// JSON keys and query values shared by several /api/v1/ui domains. Keep
// package-wide string constants here so independently written handler files
// do not redeclare them.
const (
	uiKeyAdvisories = "advisories"
	uiKeyCWE        = "cwe"
	uiKeyEcosystem  = "ecosystem"
	uiKeyPackages   = "packages"
	uiKeyPURL       = "purl"
	uiKeyRepository = "repository"
	uiKeySeverity   = "severity"
	uiKeyTitle      = "title"
	uiKeyURL        = "url"

	// uiParamOn is the "true" value of a boolean query flag (?open=1).
	uiParamOn = "1"
)
