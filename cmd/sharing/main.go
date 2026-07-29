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
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
	baseURL := flag.String("base-url", "", "public base URL of the portal, e.g. https://share.example.org (OAuth callback is <base-url>/auth/callback)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	shareCfg, err := sharing.LoadConfig(*addr, *baseURL)
	if err != nil {
		return err
	}

	gdb, err := db.OpenBackend(databaseOptions(cfg))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		return err
	}

	// The portal never runs scans. Build an inert queue against the shared DB
	// (needed only to construct the web.Server) but never start it, and a
	// worker value used only for construction; triage writes (status/notes)
	// write straight to the DB and enqueue nothing. NewNoSchema skips the goqite
	// DDL install so the portal can connect with a read-only role (the schema
	// already exists — the main app provisions it).
	q := queue.NewNoSchema(sqldb, log, 0, queueDialect(cfg))
	srv, err := web.New(gdb, q, log, web.NewBroker(), &worker.Worker{DB: gdb})
	if err != nil {
		return err
	}

	portal := sharing.New(shareCfg, gdb, log, srv.Handler())
	httpSrv := &http.Server{
		Addr:              shareCfg.Addr,
		Handler:           portal.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	log.Info("scrutineer sharing portal listening", "addr", shareCfg.Addr, "base_url", shareCfg.BaseURL)
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
