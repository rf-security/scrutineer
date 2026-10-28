package sharing

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// accessFreshTTL is how long a fetched repository list is served without
	// asking GitHub again. Changes to a visitor's GitHub access take at most
	// this long (plus one background fetch) to take effect.
	accessFreshTTL = 3 * time.Minute
	// accessMaxStale bounds how long a list may keep being served while
	// background refreshes fail. Past it, the visitor waits on a fresh fetch so
	// a prolonged GitHub outage cannot keep stale access alive indefinitely.
	accessMaxStale = 15 * time.Minute
)

// accessKey identifies one visitor's GitHub answer. The token hash means a new
// login (new token) never reads a list fetched under a previous one.
type accessKey struct {
	userID    int64
	tokenHash [sha256.Size]byte
}

func newAccessKey(userID int64, token string) accessKey {
	return accessKey{userID: userID, tokenHash: sha256.Sum256([]byte(token))}
}

// accessFlight is one in-progress GitHub fetch. found advances as pages
// arrive; repos and err are set before done is closed.
type accessFlight struct {
	done  chan struct{}
	found atomic.Int64
	repos []githubRepo
	err   error
}

type accessEntry struct {
	repos     []githubRepo
	fetchedAt time.Time     // zero until a fetch succeeds
	flight    *accessFlight // non-nil while a fetch runs
	lastErr   error         // most recent failed fetch; cleared on success
	touched   time.Time     // last fetch completion, for sweeping
}

// accessState is what the loading page polls for.
type accessState string

const (
	accessIdle         accessState = "idle"    // nothing cached and nothing running
	accessLoading      accessState = "loading" // first fetch in progress
	accessReady        accessState = "ready"   // a usable list is cached
	accessFailed       accessState = "error"   // last fetch failed transiently
	accessUnauthorized accessState = "unauthorized"
)

type accessStatus struct {
	State accessState `json:"state"`
	Found int64       `json:"found"`
}

// accessCache memoizes fetchRepositoryAccess per visitor so that a page view
// does not pay for a full, sequentially paginated GitHub listing. Fresh entries
// are served directly; stale ones are served while a single background fetch
// replaces them. Only a visitor with no usable entry has to wait on GitHub,
// and the portal shows them a progress page rather than a hung request.
type accessCache struct {
	fetch func(ctx context.Context, token string, progress func(int)) ([]githubRepo, error)
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	entries map[accessKey]*accessEntry
}

func newAccessCache(log *slog.Logger) *accessCache {
	return &accessCache{
		fetch:   fetchRepositoryAccessProgress,
		now:     time.Now,
		log:     log,
		entries: map[accessKey]*accessEntry{},
	}
}

// get returns the visitor's repository access, waiting on GitHub only when
// nothing usable is cached.
func (c *accessCache) get(ctx context.Context, userID int64, token string) ([]githubRepo, error) {
	repos, f := c.lookup(userID, token)
	if f == nil {
		return repos, nil
	}
	return f.wait(ctx)
}

// wait blocks until the flight finishes or ctx ends.
func (f *accessFlight) wait(ctx context.Context) ([]githubRepo, error) {
	select {
	case <-f.done:
		return f.repos, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// lookup never blocks. It returns the cached list, refreshing it in the
// background when stale, or — when nothing usable is cached — the flight
// fetching it (starting one if needed) and no repos.
func (c *accessCache) lookup(userID int64, token string) ([]githubRepo, *accessFlight) {
	key := newAccessKey(userID, token)
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		e = &accessEntry{}
		c.entries[key] = e
	}
	if !e.fetchedAt.IsZero() {
		age := c.now().Sub(e.fetchedAt)
		if age < accessFreshTTL {
			return e.repos, nil
		}
		if age < accessMaxStale {
			c.startLocked(key, e, token)
			return e.repos, nil
		}
	}
	return nil, c.startLocked(key, e, token)
}

// prefetch starts a fetch unless a fresh list is already cached; used at login
// so the lookup is under way before the first page is requested.
func (c *accessCache) prefetch(userID int64, token string) {
	_, _ = c.lookup(userID, token)
}

// status reports the visitor's lookup state without starting a fetch.
func (c *accessCache) status(userID int64, token string) accessStatus {
	key := newAccessKey(userID, token)
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	switch {
	case e == nil:
		return accessStatus{State: accessIdle}
	case !e.fetchedAt.IsZero() && c.now().Sub(e.fetchedAt) < accessMaxStale:
		return accessStatus{State: accessReady, Found: int64(len(e.repos))}
	case e.flight != nil:
		return accessStatus{State: accessLoading, Found: e.flight.found.Load()}
	case e.lastErr != nil && isGitHubUnauthorized(e.lastErr):
		return accessStatus{State: accessUnauthorized}
	case e.lastErr != nil:
		return accessStatus{State: accessFailed}
	default:
		return accessStatus{State: accessIdle}
	}
}

// startLocked returns the entry's running flight, starting one if none is.
func (c *accessCache) startLocked(key accessKey, e *accessEntry, token string) *accessFlight {
	if e.flight != nil {
		return e.flight
	}
	f := &accessFlight{done: make(chan struct{})}
	e.flight = f
	go c.run(key, f, token)
	return f
}

// run performs one fetch, detached from any request so a cancelled request
// does not fail the visitor's other waiting requests, and stores the result. A
// rejected token drops the cached list so the visitor re-authenticates instead
// of being served stale access; other failures keep it until accessMaxStale.
func (c *accessCache) run(key accessKey, f *accessFlight, token string) {
	repos, err := c.fetch(context.Background(), token, func(n int) { f.found.Store(int64(n)) })
	if err != nil {
		c.log.Warn("repository access fetch failed", "github_user_id", key.userID, "err", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	f.repos, f.err = repos, err
	close(f.done)

	now := c.now()
	// The entry may have been invalidated (logout) while the fetch ran; only
	// the entry that owns this flight takes its result.
	if e := c.entries[key]; e != nil && e.flight == f {
		e.flight = nil
		e.touched = now
		switch {
		case err == nil:
			e.repos, e.fetchedAt, e.lastErr = repos, now, nil
		case isGitHubUnauthorized(err):
			e.repos, e.fetchedAt, e.lastErr = nil, time.Time{}, err
		default:
			e.lastErr = err
		}
	}
	for k, e := range c.entries {
		if e.flight == nil && now.Sub(e.touched) >= accessMaxStale {
			delete(c.entries, k)
		}
	}
}

// invalidate drops the visitor's entry, e.g. on logout.
func (c *accessCache) invalidate(userID int64, token string) {
	c.mu.Lock()
	delete(c.entries, newAccessKey(userID, token))
	c.mu.Unlock()
}
