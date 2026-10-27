package sharing

import (
	"context"
	"strings"
	"testing"
	"time"

	appconfig "scrutineer/internal/config"
	"scrutineer/internal/db"
)

func TestCompileStaticGrantsResolvesExactRepositoryAndIsolatesUsers(t *testing.T) {
	gdb := openTestDB(t)
	repo := db.Repository{
		URL:     "https://github.com/Acme/Widget.git",
		HTMLURL: "https://github.com/acme/widget",
		Name:    "widget",
	}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	// A historical row may acquire the current repository's browser URL after
	// a transfer. HTMLURL is display metadata and must neither create an
	// ambiguity nor receive the grant.
	historical := db.Repository{
		URL:     "https://github.com/acme-archive/widget",
		HTMLURL: "https://github.com/acme/widget",
		Name:    "widget",
	}
	if err := gdb.Create(&historical).Error; err != nil {
		t.Fatal(err)
	}

	source, err := CompileStaticGrants(context.Background(), gdb, []appconfig.SharingAccessGrant{{
		GitHubUserID: 583231,
		Repositories: []string{"https://github.com/acme/widget"},
		Reason:       "external reviewer",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if source.UserCount() != 1 || source.RepositoryGrantCount() != 1 {
		t.Fatalf("counts = users %d, grants %d", source.UserCount(), source.RepositoryGrantCount())
	}

	ids, err := source.RepositoryIDs(context.Background(), 583231)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids[repo.ID]; !ok || len(ids) != 1 {
		t.Fatalf("granted IDs = %+v, want only %d", ids, repo.ID)
	}
	if _, ok := ids[historical.ID]; ok {
		t.Fatalf("grant matched historical row through html_url: %+v", ids)
	}
	delete(ids, repo.ID)
	idsAgain, _ := source.RepositoryIDs(context.Background(), 583231)
	if _, ok := idsAgain[repo.ID]; !ok {
		t.Fatal("caller mutated the compiled grant source")
	}
	other, _ := source.RepositoryIDs(context.Background(), 583232)
	if len(other) != 0 {
		t.Fatalf("grant leaked to another numeric user ID: %+v", other)
	}
}

func TestStaticGrantExpiresWhileServerIsRunning(t *testing.T) {
	gdb := openTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	source, err := CompileStaticGrants(context.Background(), gdb, []appconfig.SharingAccessGrant{{
		GitHubUserID: 1,
		Repositories: []string{"https://github.com/acme/widget"},
		ExpiresAt:    &expires,
	}})
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return expires.Add(time.Second) }
	ids, err := source.RepositoryIDs(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expired grant returned IDs: %+v", ids)
	}
}

func TestCompileStaticGrantsFailsClosed(t *testing.T) {
	gdb := openTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	tests := []struct {
		name   string
		grants []appconfig.SharingAccessGrant
		want   string
	}{
		{"zero user", []appconfig.SharingAccessGrant{{Repositories: []string{"https://github.com/acme/widget"}}}, "must be positive"},
		{"empty repositories", []appconfig.SharingAccessGrant{{GitHubUserID: 1}}, "must not be empty"},
		{"non GitHub URL", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://example.com/acme/widget"}}}, "exact https://github.com"},
		{"repository path suffix", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://github.com/acme/widget/issues"}}}, "exact https://github.com"},
		{"unknown repository", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://github.com/acme/missing"}}}, "not in Scrutineer"},
		{"duplicate repository", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://github.com/acme/widget", "https://github.com/ACME/WIDGET.git"}}}, "duplicate repository"},
		{"duplicate user", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://github.com/acme/widget"}}, {GitHubUserID: 1, Repositories: []string{"https://github.com/acme/widget"}}}, "duplicate github_user_id"},
		{"expired", []appconfig.SharingAccessGrant{{GitHubUserID: 1, Repositories: []string{"https://github.com/acme/widget"}, ExpiresAt: &past}}, "must be in the future"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileStaticGrants(context.Background(), gdb, tt.grants)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResolveScopeUnionsManualGrantsAndHidesGrantedReadRepo(t *testing.T) {
	gdb := openTestDB(t)
	maintained := db.Repository{URL: "https://github.com/acme/maintained", Name: "maintained"}
	readOnly := db.Repository{URL: "https://github.com/acme/read-only", Name: "read-only"}
	manualOnly := db.Repository{URL: "https://github.com/acme/manual-only", Name: "manual-only"}
	for _, repo := range []*db.Repository{&maintained, &readOnly, &manualOnly} {
		if err := gdb.Create(repo).Error; err != nil {
			t.Fatal(err)
		}
	}

	githubRepos := []githubRepo{
		{FullName: "acme/maintained", HTMLURL: maintained.URL, ViewerPermission: "WRITE"},
		{FullName: "acme/read-only", HTMLURL: readOnly.URL, ViewerPermission: "READ"},
	}
	manual := map[uint]struct{}{readOnly.ID: {}, manualOnly.ID: {}}
	scope, err := resolveScope(context.Background(), gdb, githubRepos, manual)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{maintained.ID, readOnly.ID, manualOnly.ID} {
		if _, ok := scope.RepoIDs[id]; !ok {
			t.Errorf("repository %d missing from scope %+v", id, scope.RepoIDs)
		}
	}
	if len(scope.RepoIDs) != 3 {
		t.Fatalf("scope IDs = %+v, want three", scope.RepoIDs)
	}
	if scope.AuthorizedRepoCount != 3 {
		t.Errorf("authorized count = %d, want 3", scope.AuthorizedRepoCount)
	}
	if len(scope.InsufficientRepositories) != 0 {
		t.Fatalf("manually granted READ repository shown as insufficient: %+v", scope.InsufficientRepositories)
	}
}

func TestResolveScopeMatchesOnlyPrimaryRepositoryURL(t *testing.T) {
	gdb := openTestDB(t)
	canonical := db.Repository{
		URL:     "https://github.com/rust-lang/rust-clippy",
		HTMLURL: "https://github.com/rust-lang/rust-clippy",
		Name:    "rust-clippy",
	}
	historical := db.Repository{
		URL:     "https://github.com/rust-lang-nursery/rust-clippy",
		HTMLURL: "https://github.com/rust-lang/rust-clippy",
		Name:    "rust-clippy",
	}
	for _, repo := range []*db.Repository{&canonical, &historical} {
		if err := gdb.Create(repo).Error; err != nil {
			t.Fatal(err)
		}
	}

	scope, err := resolveScope(context.Background(), gdb, []githubRepo{{
		FullName:         "rust-lang/rust-clippy",
		HTMLURL:          "https://github.com/rust-lang/rust-clippy",
		CloneURL:         "https://github.com/rust-lang/rust-clippy.git",
		ViewerPermission: "WRITE",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scope.RepoIDs[canonical.ID]; !ok {
		t.Fatalf("canonical primary URL was not matched: %+v", scope.RepoIDs)
	}
	if _, ok := scope.RepoIDs[historical.ID]; ok {
		t.Fatalf("historical row matched through html_url: %+v", scope.RepoIDs)
	}
	if len(scope.RepoIDs) != 1 {
		t.Fatalf("scope IDs = %+v, want only %d", scope.RepoIDs, canonical.ID)
	}
}
