package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// dependencyRetryTimeout is the total wait before a missing dependency is reported.
	dependencyRetryTimeout = 60 * time.Second
	// dependencyRetryBaseDelay is the first wait between attempts.
	dependencyRetryBaseDelay = 2 * time.Second
	// dependencyRetryMaxDelay is the longest single wait between attempts.
	dependencyRetryMaxDelay = 20 * time.Second
)

// dependencyRetry retries a policy upload while B2C still reports a just-created
// base policy or key container as missing.
type dependencyRetry struct {
	Timeout   time.Duration // total time to keep waiting
	BaseDelay time.Duration // first wait; doubles after each attempt
	MaxDelay  time.Duration // longest single wait

	sleep func(ctx context.Context, d time.Duration) error // nil waits on a timer
}

// defaultDependencyRetry is used by Create and Update of the policy resource.
var defaultDependencyRetry = dependencyRetry{Timeout: dependencyRetryTimeout, BaseDelay: dependencyRetryBaseDelay, MaxDelay: dependencyRetryMaxDelay}

// wait blocks for d or until ctx is done, in which case it returns ctx.Err().
func (r dependencyRetry) wait(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// do runs op until it succeeds, fails with an error isDependencyNotReady does
// not accept, the waits would exceed the timeout, or ctx is done. Errors that
// are not retried are returned as they are. When the wait ends early, the last
// error from op is wrapped, so errors.Is and errors.As still reach it.
//
// resourcex.RetryWrite is not used: it waits a fixed delay with no backoff and
// returns the last error unchanged on exhaustion and bare ctx.Err() on cancel.
func (r dependencyRetry) do(ctx context.Context, op func() error) error {
	var waited time.Duration
	delay := r.BaseDelay
	for {
		err := op()
		if err == nil || !isDependencyNotReady(err) {
			return err
		}
		if delay <= 0 || waited+delay > r.Timeout {
			return fmt.Errorf("waited %d seconds for the referenced base policy or key container to become available; the reference may be wrong: %w", int(waited.Seconds()), err)
		}
		if werr := r.wait(ctx, delay); werr != nil {
			return fmt.Errorf("%w while waiting for the referenced base policy or key container to become available: %w", werr, err)
		}
		waited += delay
		delay *= 2
		if r.MaxDelay > 0 && delay > r.MaxDelay {
			delay = r.MaxDelay
		}
	}
}

// missingPolicyMarkers are the two parts of the validation error B2C returns
// when a policy names a base policy that is not there (yet).
var missingPolicyMarkers = []string{"policy with 'policyid'", "cannot be found"}

// missingKeyMarker is part of the validation error B2C returns when a policy
// references a key container that is not there (yet).
const missingKeyMarker = "does not have cryptographickey referenced by storagereferenceid"

// isDependencyNotReady reports whether err is the Graph 400 validation error
// for a missing base policy or a missing key container. Any other error,
// including any other 400, is not retried.
func isDependencyNotReady(err error) bool {
	ae := graphAPIError(err)
	if ae == nil || ae.Status != http.StatusBadRequest {
		return false
	}
	text := strings.ToLower(ae.Body)
	if strings.Contains(text, missingKeyMarker) {
		return true
	}
	for _, m := range missingPolicyMarkers {
		if !strings.Contains(text, m) {
			return false
		}
	}
	return true
}
