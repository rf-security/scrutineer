// Package sharing implements scrutineer's external maintainer portal: a
// separate, internet-facing binary (cmd/sharing) that authenticates a visitor
// with GitHub and reuses the main scrutineer web UI, scoped to the
// repositories that visitor maintains. All GitHub/OAuth/session logic lives
// here; internal/web knows nothing about it and is unchanged for the local
// operator, gated only by the generic web.ViewScope this package injects.
package sharing

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Environment variables carrying the portal's secrets. They are read from the
// environment rather than scrutineer's YAML so credentials never sit in the
// shared config file.
const (
	envClientID     = "SCRUTINEER_SHARING_GITHUB_CLIENT_ID"
	envClientSecret = "SCRUTINEER_SHARING_GITHUB_CLIENT_SECRET"
	envSessionKey   = "SCRUTINEER_SHARING_SESSION_KEY"
)

// Config holds the portal's settings. The non-secret fields (Addr, BaseURL)
// come from cmd/sharing flags; the secrets come from the environment.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:8081".
	Addr string
	// BaseURL is the public origin the portal is served from, e.g.
	// "https://share.example.org". The GitHub OAuth callback is
	// BaseURL + "/auth/callback" and host is the origin's hostname, used for
	// the outer Host-header (DNS-rebinding) check.
	BaseURL string

	clientID     string
	clientSecret string
	host         string   // hostname parsed from BaseURL
	sessionKey   [32]byte // AES-256 key derived from envSessionKey
}

// LoadConfig assembles a Config from the given flags and the environment,
// returning an error listing every missing secret so a misconfigured deploy
// fails fast at startup rather than at first login.
func LoadConfig(addr, baseURL string) (*Config, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("sharing: -base-url is required (e.g. https://share.example.org)")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("sharing: -base-url %q is not a valid URL", baseURL)
	}

	c := &Config{
		Addr:         addr,
		BaseURL:      baseURL,
		clientID:     strings.TrimSpace(os.Getenv(envClientID)),
		clientSecret: strings.TrimSpace(os.Getenv(envClientSecret)),
		host:         u.Hostname(),
	}

	var missing []string
	if c.clientID == "" {
		missing = append(missing, envClientID)
	}
	if c.clientSecret == "" {
		missing = append(missing, envClientSecret)
	}
	if key := os.Getenv(envSessionKey); key != "" {
		// Hash to a fixed 32-byte AES-256 key so any passphrase length works.
		c.sessionKey = sha256.Sum256([]byte(key))
	} else {
		missing = append(missing, envSessionKey)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("sharing: missing required environment: %s", strings.Join(missing, ", "))
	}
	return c, nil
}
