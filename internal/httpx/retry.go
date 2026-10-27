package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	retryx "scrutineer/internal/retry"
)

const (
	defaultAttempts  = 3
	defaultBaseDelay = 200 * time.Millisecond
	defaultMaxDelay  = 2 * time.Second
)

// RetryOptions configures DoRetry. Zero values use small bounded defaults.
type RetryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Sleep     func(context.Context, time.Duration) error
}

// DoRetry performs an idempotent HTTP request with a small retry budget for
// transient upstream failures. It retries network errors and 429/502/503/504
// responses, respects Retry-After when present, and always honors req.Context().
func DoRetry(req *http.Request, opts RetryOptions) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("retry helper only supports GET, got %s", req.Method)
	}
	return doRetry(req, opts)
}

// DoRetryIdempotentPost performs a semantically idempotent POST with the same
// retry policy as DoRetry. The request body must be replayable: callers should
// construct the request with bytes.Buffer, bytes.Reader, or strings.Reader so
// http.NewRequest populates GetBody. Calling this function asserts that
// replaying the POST is safe for the application protocol.
func DoRetryIdempotentPost(req *http.Request, opts RetryOptions) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return nil, fmt.Errorf("idempotent POST retry helper only supports POST, got %s", req.Method)
	}
	if req.Body != nil && req.GetBody == nil {
		return nil, fmt.Errorf("idempotent POST retry helper requires a replayable request body")
	}
	return doRetry(req, opts)
}

func doRetry(req *http.Request, opts RetryOptions) (*http.Response, error) {
	if req.Body != nil && req.GetBody != nil {
		// Each attempt uses a fresh body below, so the original will not be sent
		// (and therefore will not be closed by http.Client.Do).
		defer func() { _ = req.Body.Close() }()
	}
	attempts := defaultedAttempts(opts.Attempts)
	baseDelay := defaultedDuration(opts.BaseDelay, defaultBaseDelay)
	maxDelay := defaultedDuration(opts.MaxDelay, defaultMaxDelay)
	sleep := opts.Sleep
	if sleep == nil {
		sleep = retryx.Sleep
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := req.Context().Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		attemptReq := req.Clone(req.Context())
		if req.Body != nil && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("recreate request body: %w", err)
			}
			attemptReq.Body = body
		}
		resp, err := http.DefaultClient.Do(attemptReq)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if attempt == attempts {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		delay := retryx.BackoffDelay(attempt, baseDelay, maxDelay)
		if err != nil {
			lastErr = err
		} else {
			delay = retryAfterDelay(resp.Header.Get("Retry-After"), delay, maxDelay)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		if err := sleep(req.Context(), delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func defaultedAttempts(attempts int) int {
	if attempts > 0 {
		return attempts
	}
	return defaultAttempts
}

func defaultedDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryAfterDelay(header string, fallback, maxDelay time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return capDelay(time.Duration(seconds)*time.Second, maxDelay)
	}
	if at, err := http.ParseTime(header); err == nil {
		delay := time.Until(at)
		if delay > 0 {
			return capDelay(delay, maxDelay)
		}
		return 0
	}
	return fallback
}

func capDelay(delay, maxDelay time.Duration) time.Duration {
	if maxDelay > 0 && delay > maxDelay {
		return maxDelay
	}
	return delay
}
