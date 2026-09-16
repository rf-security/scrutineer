package skills

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	harnessskills "github.com/alpha-omega-security/harness/skills"
	"github.com/git-pkgs/clone"
)

const (
	skillsRepoTokenEnv = "SCRUTINEER_SKILLS_REPO_TOKEN"
	askpassScript      = "#!/bin/sh\nexec printf '%s\\n' \"${" + skillsRepoTokenEnv + ":?}\"\n"
	askpassPerm        = 0o700
)

// ParseRepoSpec splits a skills_repo spec (owner/repo[@ref] or a full https
// URL) into a clone URL and optional ref. See harness/skills.ParseRepoSpec.
var ParseRepoSpec = harnessskills.ParseRepoSpec

// CloneOrPull prepares a local copy of a git repo at dst. On first call it
// clones; on subsequent calls it fetches and resets to the requested ref so
// skill updates propagate without needing to wipe the cache. When ref is
// empty the default branch is used. fullClone toggles between --depth 1 and
// full history, and unshallows an existing shallow clone when flipped to
// true. Returns the resolved commit SHA so callers can record exactly which
// version of the skills produced each scan. https-only, same rationale as
// internal/worker/clone.go (T2/T4).
func CloneOrPull(ctx context.Context, url, ref, dst string, fullClone bool, token string) (string, error) {
	return cloneOrPullWithRetry(ctx, clone.Retry{}, url, ref, dst, fullClone, token)
}

func cloneOrPullWithRetry(ctx context.Context, retry clone.Retry, url, ref, dst string, fullClone bool, token string) (string, error) {
	retry, cleanup, err := withSkillsRepoToken(retry, token, filepath.Dir(dst))
	if err != nil {
		return "", err
	}
	defer cleanup()

	if err := clone.Ensure(ctx, retry, url, dst, ref, fullClone); err != nil {
		var ue *clone.UnreachableError
		if errors.As(err, &ue) {
			return "", fmt.Errorf("skills repo %s: %w", url, ue.Err)
		}
		return "", err
	}
	sha := clone.Head(ctx, dst)
	if sha == "" {
		return "", fmt.Errorf("skills repo %s: rev-parse HEAD failed", url)
	}
	return sha, nil
}

// withSkillsRepoToken supplies private-repository credentials through
// GIT_ASKPASS. The temporary executable contains only an environment-variable
// lookup; the token itself stays out of both the script and Git's argv.
func withSkillsRepoToken(retry clone.Retry, token, askpassDir string) (clone.Retry, func(), error) {
	if token == "" {
		return retry, func() {}, nil
	}
	if strings.ContainsAny(token, "\x00\r\n") {
		return retry, func() {}, fmt.Errorf("skills repo token must be a single line")
	}

	// Keep the executable beside the skills cache because a system TMPDIR may
	// be mounted noexec. The script contains no credential and is removed below.
	if err := os.MkdirAll(askpassDir, askpassPerm); err != nil {
		return retry, func() {}, fmt.Errorf("create skills repo cache directory: %w", err)
	}
	f, err := os.CreateTemp(askpassDir, ".scrutineer-skills-askpass-*")
	if err != nil {
		return retry, func() {}, fmt.Errorf("create skills repo askpass: %w", err)
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := f.WriteString(askpassScript); err != nil {
		_ = f.Close()
		cleanup()
		return retry, func() {}, fmt.Errorf("write skills repo askpass: %w", err)
	}
	if err := f.Chmod(askpassPerm); err != nil {
		_ = f.Close()
		cleanup()
		return retry, func() {}, fmt.Errorf("chmod skills repo askpass: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return retry, func() {}, fmt.Errorf("close skills repo askpass: %w", err)
	}

	baseRun := retry.Run
	if baseRun == nil {
		baseRun = clone.Run
	}
	retry.Run = func(ctx context.Context, dir string, env []string, args ...string) (string, error) {
		// git-pkgs/clone's remoteEnv() adds GIT_TERMINAL_PROMPT=0 only to
		// remote-touching commands; keep credentials off local inspection/reset.
		if !slices.Contains(env, "GIT_TERMINAL_PROMPT=0") {
			return baseRun(ctx, dir, env, args...)
		}
		authEnv := []string{
			"GIT_ASKPASS=" + path,
			skillsRepoTokenEnv + "=" + token,
		}
		// An ambient helper that returns both fields prevents Git from invoking
		// askpass. Clear helpers for this command so the explicit token wins.
		authArgs := append([]string{"-c", "credential.helper="}, args...)
		return baseRun(ctx, dir, append(env, authEnv...), authArgs...)
	}
	return retry, cleanup, nil
}
