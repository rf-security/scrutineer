package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// CodexAccountAuthHost is used only by file-backed ChatGPT auth. The
// pinned Codex CLI refreshes subscription tokens at auth.openai.com; API-key
// runs do not need this additional destination.
const (
	CodexAccountAuthHost  = "auth.openai.com"
	codexAuthFileMode     = os.FileMode(0o600)
	maxCodexAuthFileBytes = 1 << 20
)

// CodexAccountAuth is a ChatGPT account credential shared by Codex scans.
// Codex refreshes auth.json in place, so every runner must mount the same file
// read-write. The semaphore keeps that rotating credential in a single
// serialized job stream while the rest of CODEX_HOME remains private to each
// scan.
type CodexAccountAuth struct {
	Path string
	sem  chan struct{}
}

// NewCodexAccountAuth returns shared account-auth state for a ContainerRunner.
func NewCodexAccountAuth(path string) *CodexAccountAuth {
	if path == "" {
		return nil
	}
	return &CodexAccountAuth{Path: path, sem: make(chan struct{}, 1)}
}

// acquire serializes access to the rotating credential, honours cancellation
// while another job owns it, and revalidates the file immediately before use.
func (a *CodexAccountAuth) acquire(ctx context.Context) (func(), error) {
	if a == nil {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return func() {}, err
	}
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
	if err := ValidateCodexAuthFile(a.Path); err != nil {
		<-a.sem
		return func() {}, err
	}
	return func() { <-a.sem }, nil
}

// ValidateCodexAuthFile checks the minimum properties needed for a durable
// ChatGPT login without ever returning credential material in an error.
func ValidateCodexAuthFile(path string) error {
	data, err := readCodexAuthFile(path)
	if err != nil {
		return err
	}
	// Match Codex's case-sensitive field names. Go struct decoding also
	// accepts case variants, which can shadow the fields Codex actually uses.
	var auth map[string]json.RawMessage
	if err := json.Unmarshal(data, &auth); err != nil {
		return fmt.Errorf("parse codex.auth_file: invalid JSON")
	}
	for _, key := range []string{"OPENAI_API_KEY", "personal_access_token", "bedrock_api_key", "bedrock_access_keys"} {
		if value := auth[key]; len(value) > 0 && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("codex.auth_file contains non-ChatGPT credentials (%s)", key)
		}
	}
	// Older releases omit auth_mode and infer it from the credential fields.
	// Accept that shape only after excluding every alternate mode selector.
	if value := auth["auth_mode"]; len(value) > 0 && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		var mode string
		if err := json.Unmarshal(value, &mode); err != nil || mode != "chatgpt" {
			return fmt.Errorf("codex.auth_file has invalid auth_mode; require %q", "chatgpt")
		}
	}
	var tokens map[string]json.RawMessage
	if err := json.Unmarshal(auth["tokens"], &tokens); err != nil {
		return fmt.Errorf("codex.auth_file has no ChatGPT refresh token")
	}
	var refresh string
	if err := json.Unmarshal(tokens["refresh_token"], &refresh); err != nil || strings.TrimSpace(refresh) == "" {
		return fmt.Errorf("codex.auth_file has no ChatGPT refresh token")
	}
	return nil
}

func readCodexAuthFile(path string) ([]byte, error) {
	// Check the path first: opening a FIFO can block before descriptor validation.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect codex.auth_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("codex.auth_file is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read codex.auth_file: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect codex.auth_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("codex.auth_file is not a regular file: %s", path)
	}
	if info.Mode().Perm() != codexAuthFileMode {
		// Codex rewrites this file on every refresh, so a mode change is as
		// likely to be the CLI's doing as the operator's; name the fix.
		return nil, fmt.Errorf("codex.auth_file permissions are %04o; require exactly 0600 (chmod 600 %s)", info.Mode().Perm(), path)
	}
	// The shared credential is writable by scan containers. Bound the read
	// itself so a file that grows after Stat cannot exhaust host memory.
	data, err := io.ReadAll(io.LimitReader(file, maxCodexAuthFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read codex.auth_file: %w", err)
	}
	if len(data) > maxCodexAuthFileBytes {
		return nil, fmt.Errorf("codex.auth_file exceeds %d bytes", maxCodexAuthFileBytes)
	}
	return data, nil
}
