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
	"context"
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

	dataDir := cfg.Data
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	gdb, err := db.Open(filepath.Join(dataDir, dbFileName))
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
	// write straight to the DB and enqueue nothing.
	q, err := queue.New(sqldb, log, 0)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}
	srv, err := web.New(gdb, q, log, web.NewBroker(), &worker.Worker{DB: gdb})
	if err != nil {
		return err
	}

	portal := sharing.New(shareCfg, gdb, log, srv.Handler(), grants)
	httpSrv := &http.Server{
		Addr:              shareCfg.Addr,
		Handler:           portal.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	log.Info("scrutineer sharing portal listening", "addr", shareCfg.Addr, "base_url", shareCfg.BaseURL)
	return httpSrv.ListenAndServe()
}
