package sharing

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// The loopback-only dev identity (DESIGN decision 7). LoadDevConfig refuses
// to build a Config with it unless the listen address and base URL are
// loopback, so it cannot be switched on for the internet-facing portal.

// devFetch stands in for fetchRepositoryAccessProgress: it reports the
// configured repositories as GitHub would, after AccessDelay.
func devFetch(dev *DevIdentity) func(context.Context, string, func([]githubRepo)) ([]githubRepo, error) {
	repos := make([]githubRepo, 0, len(dev.Repos))
	for _, spec := range dev.Repos {
		name, perm, _ := strings.Cut(strings.TrimSpace(spec), "=")
		if name == "" {
			continue
		}
		if perm == "" {
			perm = "ADMIN"
		}
		repos = append(repos, githubRepo{
			FullName:         name,
			HTMLURL:          "https://github.com/" + name,
			CloneURL:         "https://github.com/" + name + ".git",
			ViewerPermission: strings.ToUpper(perm),
		})
	}
	return func(ctx context.Context, _ string, progress func([]githubRepo)) ([]githubRepo, error) {
		if dev.AccessDelay > 0 {
			half := len(repos) / 2
			if err := sleepCtx(ctx, dev.AccessDelay/2); err != nil {
				return nil, err
			}
			progress(append([]githubRepo(nil), repos[:half]...))
			if err := sleepCtx(ctx, dev.AccessDelay-dev.AccessDelay/2); err != nil {
				return nil, err
			}
		}
		return append([]githubRepo(nil), repos...), nil
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// devGrants adds the dev identity's RepoIDs to the operator-configured grants.
type devGrants struct {
	inner  GrantSource
	userID int64
	ids    []uint
}

func (g devGrants) RepositoryIDs(ctx context.Context, userID int64) (map[uint]struct{}, error) {
	out, err := g.inner.RepositoryIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	if userID != g.userID || len(g.ids) == 0 {
		return out, nil
	}
	merged := make(map[uint]struct{}, len(out)+len(g.ids))
	for id := range out {
		merged[id] = struct{}{}
	}
	for _, id := range g.ids {
		merged[id] = struct{}{}
	}
	return merged, nil
}

// devLogin signs in as the dev identity without OAuth and lands on next.
func (s *Server) devLogin(w http.ResponseWriter, r *http.Request, next string) {
	token, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	dev := s.cfg.dev
	if !s.startSession(w, session{
		GitHubUserID: dev.UserID,
		Login:        dev.Login,
		Token:        "dev-" + token,
		ExpiresAt:    time.Now().Add(sessionTTL).Unix(),
	}) {
		return
	}
	s.log.Info("sharing dev login", "login", dev.Login, "github_user_id", dev.UserID)
	http.Redirect(w, r, next, http.StatusFound)
}
