package sharing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAccess drives an accessCache with a controllable clock and fetch.
type fakeAccess struct {
	mu    sync.Mutex
	now   time.Time
	calls atomic.Int32
	// release, when non-nil, blocks every fetch until it is closed.
	release chan struct{}
	repos   []githubRepo
	err     error
}

func newFakeCache(f *fakeAccess) *accessCache {
	c := newAccessCache(slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	c.fetch = func(_ context.Context, _ string, progress func(int)) ([]githubRepo, error) {
		f.calls.Add(1)
		f.mu.Lock()
		release := f.release
		f.mu.Unlock()
		progress(7)
		if release != nil {
			<-release
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.repos, f.err
	}
	return c
}

func (f *fakeAccess) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func (f *fakeAccess) set(repos []githubRepo, err error, release chan struct{}) {
	f.mu.Lock()
	f.repos, f.err, f.release = repos, err, release
	f.mu.Unlock()
}

func repoNamed(name string) []githubRepo { return []githubRepo{{FullName: name}} }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAccessCacheServesFreshEntryWithoutFetching(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0), repos: repoNamed("a/one")}
	c := newFakeCache(f)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.get(ctx, 1, "tok"); err != nil {
			t.Fatal(err)
		}
		f.advance(time.Minute)
	}
	if got := f.calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 within the fresh TTL", got)
	}
}

func TestAccessCacheStaleEntryRefreshesInBackground(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0), repos: repoNamed("a/old")}
	c := newFakeCache(f)
	ctx := context.Background()
	if _, err := c.get(ctx, 1, "tok"); err != nil {
		t.Fatal(err)
	}

	// Go stale and make the refresh hang: requests must still return the old
	// list immediately, and concurrent stale requests share one refresh.
	f.advance(accessFreshTTL)
	release := make(chan struct{})
	f.set(repoNamed("a/new"), nil, release)
	for i := 0; i < 5; i++ {
		repos, err := c.get(ctx, 1, "tok")
		if err != nil {
			t.Fatal(err)
		}
		if repos[0].FullName != "a/old" {
			t.Fatalf("stale get returned %q, want the cached a/old", repos[0].FullName)
		}
	}
	waitFor(t, func() bool { return f.calls.Load() == 2 })

	close(release)
	waitFor(t, func() bool {
		repos, _ := c.get(ctx, 1, "tok")
		return repos[0].FullName == "a/new"
	})
	if got := f.calls.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 (initial + one shared refresh)", got)
	}
}

func TestAccessCacheMissSharesOneFetch(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0)}
	release := make(chan struct{})
	f.set(repoNamed("a/one"), nil, release)
	c := newFakeCache(f)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.get(context.Background(), 1, "tok"); err != nil {
				t.Error(err)
			}
		}()
	}
	waitFor(t, func() bool { return f.calls.Load() == 1 })
	close(release)
	wg.Wait()
	if got := f.calls.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 shared by concurrent misses", got)
	}
}

func TestAccessCacheUnauthorizedRefreshEvicts(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0), repos: repoNamed("a/one")}
	c := newFakeCache(f)
	ctx := context.Background()
	if _, err := c.get(ctx, 1, "tok"); err != nil {
		t.Fatal(err)
	}

	f.advance(accessFreshTTL)
	unauthorized := &githubHTTPError{StatusCode: http.StatusUnauthorized, Endpoint: "/graphql"}
	f.set(nil, unauthorized, nil)
	if _, err := c.get(ctx, 1, "tok"); err != nil {
		t.Fatalf("stale get should still serve the cached entry, got %v", err)
	}
	waitFor(t, func() bool { return c.status(1, "tok").State == accessUnauthorized })
	if _, err := c.get(ctx, 1, "tok"); !isGitHubUnauthorized(err) {
		t.Fatalf("get after revoked token = %v, want unauthorized", err)
	}
}

func TestAccessCacheTransientRefreshFailureKeepsEntryUntilMaxStale(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0), repos: repoNamed("a/one")}
	c := newFakeCache(f)
	ctx := context.Background()
	if _, err := c.get(ctx, 1, "tok"); err != nil {
		t.Fatal(err)
	}

	outage := errors.New("github down")
	f.set(nil, outage, nil)
	f.advance(accessFreshTTL)
	if _, err := c.get(ctx, 1, "tok"); err != nil {
		t.Fatalf("stale get during outage = %v, want cached entry", err)
	}
	waitFor(t, func() bool { return f.calls.Load() == 2 })

	// Past the stale bound the request must wait on GitHub and see the error.
	f.advance(accessMaxStale)
	if _, err := c.get(ctx, 1, "tok"); !errors.Is(err, outage) {
		t.Fatalf("get past max stale = %v, want the fetch error", err)
	}
}

func TestAccessCacheKeyedByToken(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0), repos: repoNamed("a/one")}
	c := newFakeCache(f)
	ctx := context.Background()
	if _, err := c.get(ctx, 1, "tok-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get(ctx, 1, "tok-b"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls.Load(); got != 2 {
		t.Fatalf("fetches = %d, want a separate fetch per token", got)
	}

	c.invalidate(1, "tok-a")
	if _, err := c.get(ctx, 1, "tok-a"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls.Load(); got != 3 {
		t.Fatalf("fetches = %d, want a refetch after invalidate", got)
	}
}

func TestAccessCacheStatusReportsProgress(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0)}
	release := make(chan struct{})
	f.set(repoNamed("a/one"), nil, release)
	c := newFakeCache(f)

	if st := c.status(1, "tok"); st.State != accessIdle {
		t.Fatalf("status before any lookup = %+v, want idle", st)
	}
	if _, flight := c.lookup(1, "tok"); flight == nil {
		t.Fatal("lookup with nothing cached returned no flight")
	}
	waitFor(t, func() bool { return c.status(1, "tok") == accessStatus{State: accessLoading, Found: 7} })

	close(release)
	waitFor(t, func() bool { return c.status(1, "tok").State == accessReady })
	if repos, flight := c.lookup(1, "tok"); flight != nil || len(repos) != 1 {
		t.Fatalf("lookup after fetch = (%v, %v), want cached repos and no flight", repos, flight)
	}
}

func TestAccessCacheFailedFirstFetchReportsErrorThenRetries(t *testing.T) {
	f := &fakeAccess{now: time.Unix(1000, 0)}
	f.set(nil, errors.New("github down"), nil)
	c := newFakeCache(f)

	_, flight := c.lookup(1, "tok")
	<-flight.done
	if st := c.status(1, "tok"); st.State != accessFailed {
		t.Fatalf("status after failed first fetch = %+v, want error", st)
	}
	f.set(repoNamed("a/one"), nil, nil)
	if _, err := c.get(context.Background(), 1, "tok"); err != nil {
		t.Fatalf("retry after failure = %v", err)
	}
	if got := f.calls.Load(); got != 2 {
		t.Fatalf("fetches = %d, want a new fetch after the failure", got)
	}
}
