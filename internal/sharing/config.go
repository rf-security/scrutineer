// Package sharing implements scrutineer's external maintainer portal: a
// separate, internet-facing binary (cmd/sharing) that authenticates a visitor
// with GitHub and reuses the main scrutineer web UI, scoped to the
// repositories that visitor maintains. All GitHub/OAuth/session logic lives
// here; internal/web knows nothing about it and is unchanged for the local
// operator, gated only by the generic web.ViewScope this package injects.
package sharing

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
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

	// UI selects the front end: UISPA (default) serves the embedded portal
	// SPA at / with the JSON auth endpoints; UILegacy keeps the server-rendered
	// HTML portal (templates/sharing) for one release.
	UI UIMode

	// Version, Commit and CommitDate are reported by GET /auth/session.
	Version, Commit, CommitDate string

	clientID     string
	clientSecret string
	host         string   // hostname parsed from BaseURL
	sessionKey   [32]byte // AES-256 key derived from envSessionKey

	// dev, when set, replaces GitHub with a fixed identity (LoadDevConfig).
	dev *DevIdentity
	// insecureCookies drops the Secure attribute so cookies work over plain
	// http on loopback. Only LoadDevConfig sets it.
	insecureCookies bool
}

// UIMode is the -ui flag.
type UIMode string

const (
	UISPA    UIMode = "spa"
	UILegacy UIMode = "legacy"
)

// ParseUIMode validates a -ui flag value.
func ParseUIMode(v string) (UIMode, error) {
	switch UIMode(v) {
	case UISPA, UILegacy:
		return UIMode(v), nil
	}
	return "", fmt.Errorf("sharing: -ui must be %q or %q, got %q", UISPA, UILegacy, v)
}

func (c *Config) legacy() bool { return c.UI == UILegacy }

// DevIdentity fakes GitHub for local development (DESIGN decision 7): /auth/login
// signs in as Login/UserID without OAuth, and the "GitHub" repository lookup
// reports Repos. RepoIDs are granted directly, like sharing.access_grants.
type DevIdentity struct {
	Login  string
	UserID int64
	// Repos are GitHub full names ("owner/name"), each optionally suffixed with
	// "=PERMISSION" (ADMIN, MAINTAIN, WRITE, TRIAGE or READ; default ADMIN).
	// They match Scrutineer repositories whose URL is github.com/owner/name.
	Repos []string
	// RepoIDs are Scrutineer repository IDs granted to the dev user.
	RepoIDs []uint
	// AccessDelay makes the fake lookup take this long (half the repos are
	// reported halfway), to exercise the SPA's progress and partial states.
	AccessDelay time.Duration
}

// LoadDevConfig assembles a Config for the loopback-only dev identity. It
// refuses any listen address or base URL that is not loopback, needs no
// GitHub OAuth secrets, and uses a random session key unless
// SCRUTINEER_SHARING_SESSION_KEY is set. Cookies drop Secure so they work
// over http://127.0.0.1.
func LoadDevConfig(addr, baseURL string, dev DevIdentity) (*Config, error) {
	if !isLoopbackAddr(addr) {
		return nil, fmt.Errorf("sharing: the dev identity only runs on a loopback -addr (e.g. 127.0.0.1:8081), got %q", addr)
	}
	if strings.TrimSpace(dev.Login) == "" {
		return nil, fmt.Errorf("sharing: the dev identity needs a login")
	}
	if dev.UserID <= 0 {
		return nil, fmt.Errorf("sharing: the dev identity needs a positive GitHub user id")
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "http://" + addr
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("sharing: -base-url %q is not a valid URL", baseURL)
	}
	if !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("sharing: the dev identity needs a loopback -base-url, got %q", baseURL)
	}
	c := &Config{
		Addr:            addr,
		BaseURL:         baseURL,
		host:            u.Hostname(),
		dev:             &dev,
		insecureCookies: true,
	}
	if key := os.Getenv(envSessionKey); key != "" {
		c.sessionKey = sha256.Sum256([]byte(key))
	} else if _, err := rand.Read(c.sessionKey[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// isLoopbackAddr reports whether a listen address binds only loopback. An
// empty host (":8081") binds every interface and is refused.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
