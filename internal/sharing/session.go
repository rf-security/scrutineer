package sharing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// session is the authenticated state sealed into the visitor's cookie. The
// GitHub OAuth token is stored here (encrypted) so the portal can re-check the
// visitor's maintained repositories on every request for real-time tracking.
// The short TTL bounds how long a stolen token could be replayed.
type session struct {
	Login     string `json:"l"`
	Token     string `json:"t"` // GitHub OAuth access token
	ExpiresAt int64  `json:"e"` // unix seconds
}

const (
	sessionCookie = "scrutineer_sharing"
	stateCookie   = "scrutineer_sharing_state"
	// sessionTTL bounds how long a resolved repo scope is trusted before the
	// visitor must re-authenticate and have their GitHub access re-checked.
	sessionTTL = 45 * time.Minute
	stateTTL   = 10 * time.Minute
)

// seal serialises and encrypts s into a URL-safe cookie value with AES-GCM.
func (c *Config) seal(s session) (string, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	gcm, err := c.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts and validates a cookie value produced by seal, rejecting
// tampered or expired sessions.
func (c *Config) open(v string) (session, error) {
	var s session
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return s, err
	}
	gcm, err := c.aead()
	if err != nil {
		return s, err
	}
	if len(raw) < gcm.NonceSize() {
		return s, errors.New("sharing: malformed session")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(plain, &s); err != nil {
		return s, err
	}
	if time.Now().Unix() > s.ExpiresAt {
		return s, errors.New("sharing: session expired")
	}
	return s, nil
}

func (c *Config) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.sessionKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
