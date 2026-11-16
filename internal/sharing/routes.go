package sharing

// The portal's whole forwarded surface. It is GET-only and default-deny:
// anything not listed here 404s at the portal and never reaches the reused
// inner handler. Every route carries a resourceKind so authorize resolves the
// {id} in its path to a repository and checks it against the visitor's scope
// before forwarding; the client is never trusted. The ReadOnly view scope,
// requireOperator failing closed on non-GET, denyReadOnly and the read-only
// database role all refuse writes again behind this list.
//
// openapi.portal.yaml (repo root) is generated from openapi.yaml filtered to
// apiRoutes, plus openapi_auth.yaml for the auth endpoints and downloadRoutes;
// see openapi_gen.go and TestPortalOpenAPIGolden.

// resourceKind classifies a forwarded route so the authorization middleware
// knows how to resolve the {id} in its path to a repository ID.
type resourceKind int

const (
	kindList    resourceKind = iota // list routes; scoped by the query filter, no {id}
	kindRepo                        // {id} is a repository ID
	kindFinding                     // {id} is a finding ID
	kindScan                        // {id} is a scan ID (resolved to its repository)
	kindStatic                      // no {id} and no repository data (vocabularies); auth only
)

// route is an allow-listed pattern forwarded to the reused handler.
type route struct {
	pattern string
	kind    resourceKind
}

// apiPrefix is where the inner handler mounts the v2 JSON API.
const apiPrefix = "/api/v1/ui/"

// apiRoutes is the /api/v1/ui surface the SPA reads (DESIGN §3.1). Every
// pattern was checked against the inner mux (TestAllowListExistsInInnerMux);
// none of the designed routes was missing, so none was dropped.
//
// Deliberately absent (DESIGN §3.2): search, events, activity, meta/dynamic,
// session, _test/publish, labels, audit; the orgs, maintainers, packages,
// advisories, sboms, skills, settings, usage, reporting, benchmark and
// investigations sections; every conversation route; repository blob, tree,
// workbench, scan-config, compliance, expected, conversations and branches;
// finding exposures, submissions, labels, vince, akrites and conversations;
// scan refusal-audit.
var apiRoutes = []route{
	{"GET /api/v1/ui/meta", kindStatic},
	{"GET /api/v1/ui/meta/cwe", kindStatic},

	{"GET /api/v1/ui/repositories", kindList},
	{"GET /api/v1/ui/findings", kindList},
	{"GET /api/v1/ui/scans", kindList},

	{"GET /api/v1/ui/repositories/{id}", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/findings", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/scans", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/dependencies", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/packages", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/dependents", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/advisories", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/maintainers", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/alternatives", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/subprojects", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/threat-model", kindRepo},
	{"GET /api/v1/ui/repositories/{id}/metadata", kindRepo},

	{"GET /api/v1/ui/findings/{id}", kindFinding},
	{"GET /api/v1/ui/findings/{id}/history", kindFinding},
	{"GET /api/v1/ui/findings/{id}/notes", kindFinding},
	{"GET /api/v1/ui/findings/{id}/communications", kindFinding},
	{"GET /api/v1/ui/findings/{id}/references", kindFinding},
	{"GET /api/v1/ui/findings/{id}/reviews", kindFinding},
	{"GET /api/v1/ui/findings/{id}/verifications", kindFinding},
	{"GET /api/v1/ui/findings/{id}/observations", kindFinding},
	{"GET /api/v1/ui/findings/{id}/attack-paths", kindFinding},
	{"GET /api/v1/ui/findings/{id}/remediation", kindFinding},
	{"GET /api/v1/ui/findings/{id}/migration-guide", kindFinding},

	{"GET /api/v1/ui/scans/{id}", kindScan},
	{"GET /api/v1/ui/scans/{id}/log", kindScan},
	{"GET /api/v1/ui/scans/{id}/prompt", kindScan},
	{"GET /api/v1/ui/scans/{id}/report", kindScan},
}

// downloadRoutes are the legacy file downloads, served in both UI modes.
var downloadRoutes = []route{
	{"GET /repositories/{id}/report.md", kindRepo},
	{"GET /findings/{id}/report.md", kindFinding},
	{"GET /findings/{id}/csaf.json", kindFinding},
	{"GET /findings/{id}/osv.json", kindFinding},
	{"GET /findings/{id}/bundle.tar.gz", kindFinding},
	{"GET /findings/{id}/patch.diff", kindFinding},
	{"GET /scans/{id}/report.md", kindScan},
}

// legacyPageRoutes are the server-rendered HTML pages, forwarded only with
// -ui=legacy. In SPA mode these paths are client routes served index.html.
var legacyPageRoutes = []route{
	{"GET /{$}", kindList},
	{"GET /findings", kindList},
	{"GET /repositories/{id}", kindRepo},
	{"GET /findings/{id}", kindFinding},
	{"GET /scans", kindList},
	{"GET /scans/{id}", kindScan},
}

// downloadSuffixes are the file extensions of downloadRoutes. A GET for an
// unknown path with one of them 404s instead of falling back to the SPA
// document, so a mistyped download never comes back as HTML.
var downloadSuffixes = []string{".md", ".json", ".tar.gz", ".diff"}
