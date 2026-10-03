// Package testutil holds helpers shared by the internal/* test suites.
// It is imported only from _test.go files.
package testutil

import (
	"os"
	"strconv"
)

// GitEnv returns an environment for exec'd git commands in tests: it
// suppresses the host's global/system git config and background maintenance,
// and pins author/committer identity so commits are reproducible regardless
// of the developer's or CI runner's local git setup.
func GitEnv() []string {
	env := append([]string{}, os.Environ()...)
	// Preserve runtime config such as fixture-local URL rewrites.
	count, err := strconv.Atoi(os.Getenv("GIT_CONFIG_COUNT"))
	if err != nil || count < 0 {
		count = 0
	}
	for _, setting := range []struct{ key, value string }{
		{"maintenance.auto", "false"},
		{"gc.auto", "0"},
	} {
		index := strconv.Itoa(count)
		env = append(env, "GIT_CONFIG_KEY_"+index+"="+setting.key, "GIT_CONFIG_VALUE_"+index+"="+setting.value)
		count++
	}
	return append(env,
		"GIT_CONFIG_COUNT="+strconv.Itoa(count),
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Scrutineer Tests",
		"GIT_AUTHOR_EMAIL=scrutineer-tests@example.invalid",
		"GIT_COMMITTER_NAME=Scrutineer Tests",
		"GIT_COMMITTER_EMAIL=scrutineer-tests@example.invalid",
	)
}
