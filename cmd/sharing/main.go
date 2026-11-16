// Command sharing is scrutineer's external maintainer portal: a separate,
// internet-facing web server that authenticates a visitor with GitHub and
// serves the existing scrutineer findings/repository pages scoped to the
// repositories that visitor maintains. It shares the main app's database and
// web handlers (internal/web) but runs as its own process on its own port;
// the local scrutineer app and its data are unchanged.
//
// It reads DB + data-dir settings from the same scrutineer YAML config (for
// -config) and its own OAuth/session secrets from the environment:
//
//	SCRUTINEER_SHARING_GITHUB_CLIENT_ID
//	SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET
//	SCRUTINEER_SHARING_SESSION_KEY
//
// The GitHub OAuth App's callback URL must be <base-url>/auth/callback.
//
// -ui=spa (default) serves the embedded portal SPA (internal/sharing/ui/dist,
// or SCRUTINEER_SHARING_UI_DIR) at / over the JSON allow-list; -ui=legacy
// keeps the server-rendered HTML portal for one release.
//
// For local development, -dev-login fakes the GitHub identity and repository
// list instead of OAuth (no GitHub secrets needed). It refuses to start unless
// -addr is a loopback address:
//
//	go run ./cmd/sharing -addr 127.0.0.1:8081 -dev-login octocat \
//	  -dev-repos owner/repo,owner/other=READ -dev-repo-ids 1,2
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/sharing"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

const (
	dbFileName        = "scrutineer.db"
	defaultDataDir    = "./data"
	readHeaderTimeout = 10 * time.Second
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	configPath := flag.String("config", config.DefaultPath, "path to the scrutineer YAML config (for database + data dir)")
	addr := flag.String("addr", "127.0.0.1:8081", "listen address for the sharing portal")
	baseURL := flag.String("base-url", "", "public base URL of the portal, e.g. https://share.example.org (OAuth callback is <base-url>/auth/callback); defaults to http://<addr> with -dev-login")
	uiMode := flag.String("ui", string(sharing.UISPA), "front end: spa (embedded portal SPA) or legacy (server-rendered HTML portal)")
	devLogin := flag.String("dev-login", "", "DEVELOPMENT ONLY: sign every visitor in as this fake GitHub login without OAuth; requires a loopback -addr")
	devUserID := flag.Int64("dev-user-id", 1, "with -dev-login: the fake numeric GitHub user id")
	devRepos := flag.String("dev-repos", "", "with -dev-login: comma-separated GitHub repos (owner/name[=ADMIN|MAINTAIN|WRITE|TRIAGE|READ], default ADMIN) the fake lookup reports")
	devRepoIDs := flag.String("dev-repo-ids", "", "with -dev-login: comma-separated scrutineer repository ids granted to the fake user")
	devDelay := flag.Duration("dev-access-delay", 0, "with -dev-login: how long the fake repository lookup takes (exercises the progress and partial states)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	mode, err := sharing.ParseUIMode(*uiMode)
	if err != nil {
		return err
	}
	var shareCfg *sharing.Config
	if *devLogin != "" {
		ids, err := parseRepoIDs(*devRepoIDs)
		if err != nil {
			return err
		}
		shareCfg, err = sharing.LoadDevConfig(*addr, *baseURL, sharing.DevIdentity{
			Login:       *devLogin,
			UserID:      *devUserID,
			Repos:       splitList(*devRepos),
			RepoIDs:     ids,
			AccessDelay: *devDelay,
		})
		if err != nil {
			return err
		}
		log.Warn("DEV IDENTITY ENABLED: every visitor is signed in as a fake GitHub user; never expose this process",
			"login", *devLogin, "github_user_id", *devUserID, "repos", *devRepos, "repo_ids", *devRepoIDs)
	} else {
		shareCfg, err = sharing.LoadConfig(*addr, *baseURL)
		if err != nil {
			return err
		}
	}
	shareCfg.UI = mode
	shareCfg.Version, shareCfg.Commit, shareCfg.CommitDate = buildVersion()

	gdb, err := db.OpenBackend(databaseOptions(cfg))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		return err
	}
	grants, err := sharing.CompileStaticGrants(context.Background(), gdb, cfg.Sharing.AccessGrants)
	if err != nil {
		return err
	}
	log.Info("sharing access grants loaded",
		"users", grants.UserCount(),
		"repository_grants", grants.RepositoryGrantCount())

	// The portal never runs scans. Build an inert queue against the shared DB
	// (needed only to construct the web.Server) but never start it, and a
	// worker value used only for construction; triage writes (status/notes)
	// write straight to the DB and enqueue nothing. NewNoSchema skips the goqite
	// DDL install so the portal can connect with a read-only role (the schema
	// already exists — the main app provisions it).
	q := queue.NewNoSchema(sqldb, log, 0, queueDialect(cfg))
	// The portal renders its own template set (templates/sharing/), kept
	// separate from the main UI so portal-specific markup can diverge without
	// touching the operator templates.
	srv, err := web.New(gdb, q, log, web.NewBroker(), &worker.Worker{DB: gdb},
		web.WithTemplateGlob("templates/sharing/*.html"))
	if err != nil {
		return err
	}

	portal := sharing.New(shareCfg, gdb, log, srv.Handler(), grants)
	httpSrv := &http.Server{
		Addr:              shareCfg.Addr,
		Handler:           portal.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	log.Info("scrutineer sharing portal listening", "addr", shareCfg.Addr, "base_url", shareCfg.BaseURL, "ui", mode)
	return httpSrv.ListenAndServe()
}

// databaseOptions maps the scrutineer config onto db.OpenBackend's Options for
// the portal. It uses the sharing-resolved database (the root database config
// overlaid with any sharing.database overrides), so the portal can run against
// its own credentials while defaulting to the main database. sqlite still lives
// under the data directory, matching cmd/scrutineer.
func databaseOptions(cfg *config.Config) db.Options {
	dbCfg := cfg.SharingDatabase()
	if dbCfg.Driver == "postgres" {
		return db.Options{Dialect: db.DialectPostgres, DSN: dbCfg.DSN}
	}
	dataDir := cfg.Data
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	return db.Options{Dialect: db.DialectSQLite, DSN: filepath.Join(dataDir, dbFileName)}
}

func queueDialect(cfg *config.Config) queue.Dialect {
	if cfg.SharingDatabase().Driver == "postgres" {
		return queue.Postgres
	}
	return queue.SQLite
}

// version is replaced with -ldflags -X main.version=... in release builds.
var version = "dev"

// buildVersion reports the version and VCS stamp for GET /auth/session.
func buildVersion() (v, commit, date string) {
	v = version
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.time":
				date = s.Value
			}
		}
	}
	return v, commit, date
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseRepoIDs(v string) ([]uint, error) {
	var out []uint
	for _, part := range splitList(v) {
		id, err := strconv.ParseUint(part, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("sharing: -dev-repo-ids: %q is not a repository id", part)
		}
		out = append(out, uint(id))
	}
	return out, nil
}
