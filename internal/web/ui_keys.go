package web

// JSON keys and query values shared by several /api/v1/ui domains. Keep
// package-wide string constants here so independently written handler files
// do not redeclare them.
const (
	uiKeyCWE      = "cwe"
	uiKeyPackages = "packages"
	uiKeyTitle    = "title"
	uiKeyURL      = "url"

	// uiParamOn is the "true" value of a boolean query flag (?open=1).
	uiParamOn = "1"
)
