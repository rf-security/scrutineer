package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"scrutineer/internal/coverage"
)

const backendProbeAnswer = "SCRUTINEER_BACKEND_READY"

const (
	backendProbeOutputLimit    = 1 << 20
	backendProbeDirMode        = 0700
	backendProbeCleanupTimeout = 10 * time.Second
)

// Preserve the real tool/permission configuration, but not scan instructions,
// resume state, repository data or callback tokens.
func backendProbeJob(sj SkillJob) SkillJob {
	job := SkillJob{Model: sj.Model, Effort: sj.Effort, AllowedTools: sj.AllowedTools, MaxTurns: 1,
		Prompt: "Reply with exactly " + backendProbeAnswer + ". Do not use tools, read files, or write files."}
	if sj.OutputFile != "" {
		job.OutputFile = "probe.json"
	}
	return job
}

func blockedBackendProbe(reason string) coverage.BackendProbe {
	return coverage.BackendProbe{Status: coverage.PreflightBlocked, Error: reason}
}

// Raw agent output and process errors can contain secrets. Only fixed failure
// categories and usage counters escape this function.
func runBackendProbe(ctx context.Context, h Harness, binary string, args, env []string, work string) coverage.BackendProbe {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = work, env
	cmd.WaitDelay = time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return blockedBackendProbe("could not open backend output")
	}
	cmd.Stderr = io.Discard
	terminate, err := startBackendProbe(cmd)
	if err != nil {
		return blockedBackendProbe("could not start backend")
	}
	defer terminate()
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stop()
	result := blockedBackendProbe("backend did not return the expected terminal response")
	var terminal, answer, failed bool
	var rateLimit *RateLimitInfo
	limited := &io.LimitedReader{R: out, N: backendProbeOutputLimit}
	h.ParseStream(limited, func(e Event) {
		switch e.Kind {
		case KindText:
			answer = answer || strings.TrimSpace(e.Text) == backendProbeAnswer
		case KindResult:
			terminal = true
			answer = answer || strings.TrimSpace(e.Text) == backendProbeAnswer
			result.CostUSD += e.CostUSD
			result.InputTokens += e.Usage.InputTokens
			result.OutputTokens += e.Usage.OutputTokens
			result.CacheReadTokens += e.Usage.CacheReadTokens
			result.CacheWriteTokens += e.Usage.CacheWriteTokens
		case KindTool:
			result.Error = "backend attempted a tool call during the probe"
			failed = true
			cancel()
		case KindError:
			result.Error = "backend reported a request error"
			failed = true
			cancel()
		case KindRateLimit:
			if e.RateLimit.Rejected() {
				rateLimit = preferRateLimitReset(rateLimit, e.RateLimit)
				result.RateLimited = true
				result.RateLimitResetAt = rateLimit.ResetTime()
				result.Error = "backend rate limit rejected the request"
				failed = true
				cancel()
			}
		}
	})
	if limited.N == 0 {
		result.Error = "backend output exceeded the probe limit"
		failed = true
		cancel()
	}
	_ = out.Close()
	if err := cmd.Wait(); err == nil && terminal && answer && !failed && ctx.Err() == nil {
		result.Status, result.Error = coverage.PreflightReady, ""
	}
	return result
}

// Unreadable or oversized credential/config files disable reuse, not the probe.
func credentialFileIdentity(path string) string {
	info, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		return "absent"
	}
	if statErr != nil || !info.Mode().IsRegular() {
		return randomProbeID()
	}
	f, err := os.Open(path)
	if err != nil {
		return randomProbeID()
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, backendProbeOutputLimit+1))
	if err != nil || len(b) > backendProbeOutputLimit {
		return randomProbeID()
	}
	return textDigest(string(b))
}

func backendEnvironment(h Harness, baseURL string, overrides map[string]string) map[string]string {
	env := make(map[string]string)
	for _, entry := range h.Env(baseURL) {
		k, v, assignment := strings.Cut(entry, "=")
		if !assignment {
			v = os.Getenv(k)
		}
		env[k] = v
	}
	for k, v := range overrides {
		env[k] = v
	}
	return env
}

func (l LocalClaude) checkBackendPreflight(ctx context.Context, sj SkillJob) error {
	if sj.checkBackend == nil {
		return nil
	}
	job := backendProbeJob(sj)
	h := ClaudeHarness{}
	args := h.Args(job.toJob(l.Effort, 1, ""))
	home, _ := os.UserHomeDir()
	configDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join(home, ".claude")
	}
	binary, _ := exec.LookPath(h.Binary())
	binaryIdentity := randomProbeID()
	if info, err := os.Stat(binary); err == nil {
		binaryIdentity = fmt.Sprintf("%s:%d:%d", binary, info.Size(), info.ModTime().UnixNano())
	}
	config, err := json.Marshal(struct {
		Args                                  []string
		Env                                   []string
		Binary, Credentials, Settings, Config string
	}{Args: args, Env: os.Environ(), Binary: binaryIdentity,
		Credentials: credentialFileIdentity(filepath.Join(configDir, ".credentials.json")),
		Settings:    credentialFileIdentity(filepath.Join(configDir, "settings.json")),
		Config:      credentialFileIdentity(filepath.Join(home, ".claude.json"))})
	if err != nil {
		return err
	}
	return sj.checkBackend(ctx, config, func(ctx context.Context) coverage.BackendProbe {
		work, err := os.MkdirTemp("", "scrutineer-backend-probe-")
		if err != nil {
			return blockedBackendProbe("could not prepare probe workspace")
		}
		defer func() { _ = os.RemoveAll(work) }()
		return runBackendProbe(ctx, h, h.Binary(), args, os.Environ(), work)
	})
}

func (d ContainerRunner) checkBackendPreflight(ctx context.Context, sj SkillJob, image string, hnet hardenedNet, provider opencodeProvider, stableProxy string) error {
	if sj.checkBackend == nil {
		return nil
	}
	job := backendProbeJob(sj)
	h := d.harness()
	inspectCtx, cancel := context.WithTimeout(ctx, capabilityProbeTimeout)
	digest := runnerImageContentDigest(inspectCtx, d.Runtime, image)
	cancel()
	if digest == "" {
		digest = randomProbeID()
	}
	credentials := map[string]string{}
	if provider.StateDir != "" {
		credentials["opencode"] = credentialFileIdentity(opencodeProviderAuthPath(provider.StateDir))
	}
	if d.CodexAccountAuth != nil {
		credentials["codex"] = credentialFileIdentity(d.CodexAccountAuth.Path)
	}
	config, err := json.Marshal(struct {
		Backend, Image, Digest, Proxy, BaseURL     string
		Model, AllowedTools                        string
		Args                                       []string
		Env, Credentials                           map[string]string
		Provider                                   OpencodeProviderConfig
		Runtime                                    ContainerRuntime
		Hardened, RuntimeOnly, Relabel             bool
		Egress                                     EgressSidecarConfig
		ProviderAllow, ProviderAPIHosts            []string
		HostGateway, ProviderHost, ProviderAPIPort string
		ModelProxyURL                              string
	}{Backend: HarnessName(h), Image: image, Digest: digest, Proxy: stableProxy, BaseURL: d.ModelBaseURL,
		Model: job.Model, AllowedTools: job.AllowedTools,
		Args: d.harnessArgv(job), Env: backendEnvironment(h, d.ModelBaseURL, provider.Env), Credentials: credentials,
		Provider: d.OpencodeProviders[provider.ID], Runtime: d.Runtime, Hardened: d.Hardened,
		RuntimeOnly: d.HardenedRuntimeOnly, Relabel: d.SELinuxRelabel, Egress: d.Egress,
		ProviderAllow: d.ProviderProxy.Allow, ProviderAPIHosts: d.ProviderProxy.APIHosts,
		HostGateway: d.HostGatewayIP, ProviderHost: d.ProviderProxy.ContainerHost, ProviderAPIPort: d.ProviderProxy.APIPort,
		ModelProxyURL: d.ModelProxyURL})
	if err != nil {
		return err
	}
	return sj.checkBackend(ctx, config, func(ctx context.Context) coverage.BackendProbe {
		// Keep interrupted probes within the existing scan-workspace lifecycle.
		// Only work/ is mounted, never its parent or the scan's src/context.
		root, err := os.MkdirTemp(sj.WorkRoot, ".backend-probe-")
		if err != nil {
			return blockedBackendProbe("could not prepare probe workspace")
		}
		defer func() { _ = os.RemoveAll(root) }()
		work, state := filepath.Join(root, "work"), filepath.Join(root, "state")
		if err := os.MkdirAll(work, backendProbeDirMode); err != nil {
			return blockedBackendProbe("could not prepare probe workspace")
		}
		if err := os.MkdirAll(state, backendProbeDirMode); err != nil {
			return blockedBackendProbe("could not prepare probe state")
		}
		if err := prepareOpencodeScanState(provider, state); err != nil {
			return blockedBackendProbe("could not prepare backend credentials")
		}
		base := d.buildRunArgsForProvider(work, image, hnet, state, provider, "/work")
		name := "scrutineer-backend-probe-" + randomProbeID()
		delimiter := slices.Index(base, "--")
		if delimiter < 0 {
			return blockedBackendProbe("container arguments missing option delimiter")
		}
		base = slices.Insert(base, delimiter, "--name", name)
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), backendProbeCleanupTimeout)
			defer cancel()
			_ = exec.CommandContext(cleanupCtx, runtimeBin(d.Runtime), "rm", "--force", name).Run()
		}()
		return runBackendProbe(ctx, h, runtimeBin(d.Runtime), append(base, d.harnessArgv(job)...), environmentWith(os.Environ(), d.containerProcessEnv(provider.Env)), work)
	})
}
