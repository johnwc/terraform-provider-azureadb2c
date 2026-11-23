package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/terraprovider/go-msadmin/httpx"
)

func TestIsDependencyNotReady(t *testing.T) {
	apiErr := func(status int, body string) error {
		return &httpx.APIError{Status: status, Body: body, Message: "microsoft graph POST /trustFramework/policies: " + body}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"missing base policy", apiErr(http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_EXT\" of tenant \"contoso.onmicrosoft.com\".Policy with 'policyId': B2C_1A_BASE cannot be found in the directory '00000000-0000-0000-0000-000000000000'."}}`), true},
		{"missing key container", apiErr(http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_BASE\" of tenant \"contoso.onmicrosoft.com\".Tenant \"contoso.onmicrosoft.com\" does not have CryptographicKey referenced by storageReferenceId \"B2C_1A_TokenSigningKeyContainer\". "}}`), true},
		{"other validation error", apiErr(http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_X\" of tenant \"contoso.onmicrosoft.com\".A policy must have a technical profile."}}`), false},
		{"base policy other problem", apiErr(http.StatusBadRequest, `Neither the policy nor any of its base policy elements define ClaimType 'x'.`), false},
		{"missing key set on read", apiErr(http.StatusBadRequest, `{"error":{"code":"AADB2C90073","message":"KeyContainer with 'id': 'B2C_1A_x' cannot be found in the directory 'contoso.onmicrosoft.com'."}}`), false},
		{"404 with the same text", apiErr(http.StatusNotFound, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_EXT\" of tenant \"contoso.onmicrosoft.com\".Policy with 'policyId': B2C_1A_BASE cannot be found in the directory '00000000-0000-0000-0000-000000000000'."}}`), false},
		{"500 with the same text", apiErr(http.StatusInternalServerError, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_EXT\" of tenant \"contoso.onmicrosoft.com\".Policy with 'policyId': B2C_1A_BASE cannot be found in the directory '00000000-0000-0000-0000-000000000000'."}}`), false},
		{"path is not body", &httpx.APIError{Status: http.StatusBadRequest, Body: "bad request", Message: "microsoft graph PUT /trustFramework/policies/B2C_1A_x/$value: Policy with 'policyId': x cannot be found"}, false},
		{"not an API error", errors.New("Policy with 'policyId': x cannot be found"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDependencyNotReady(tc.err); got != tc.want {
				t.Errorf("isDependencyNotReady = %v; want %v", got, tc.want)
			}
		})
	}
}

// recordingRetry returns a retry whose waits are recorded instead of slept.
func recordingRetry(timeout time.Duration, waits *[]time.Duration) dependencyRetry {
	return dependencyRetry{
		Timeout:   timeout,
		BaseDelay: time.Second,
		MaxDelay:  4 * time.Second,
		sleep: func(ctx context.Context, d time.Duration) error {
			*waits = append(*waits, d)
			return ctx.Err()
		},
	}
}

func TestDependencyRetryRetriesUntilSuccess(t *testing.T) {
	notReady := &httpx.APIError{Status: http.StatusBadRequest, Body: "Policy with 'policyId': B2C_1A_BASE cannot be found in the directory"}
	var waits []time.Duration
	calls := 0
	err := recordingRetry(time.Minute, &waits).do(context.Background(), func() error {
		calls++
		if calls < 2 {
			return notReady
		}
		return nil
	})
	if err != nil || calls != 2 || len(waits) != 1 {
		t.Errorf("err = %v, calls = %d, waits = %v; want nil after 2 calls and 1 wait", err, calls, waits)
	}
}

func TestDependencyRetryStopsOnOtherErrors(t *testing.T) {
	other := &httpx.APIError{Status: http.StatusBadRequest, Body: "schema validation failed"}
	var waits []time.Duration
	calls := 0
	err := recordingRetry(time.Minute, &waits).do(context.Background(), func() error {
		calls++
		return other
	})
	if err != error(other) || calls != 1 || len(waits) != 0 {
		t.Errorf("err = %v, calls = %d, waits = %v; want the error unchanged after 1 call", err, calls, waits)
	}
}

func TestDependencyRetryGivesUp(t *testing.T) {
	notReady := &httpx.APIError{Status: http.StatusBadRequest, Body: `Tenant "contoso.onmicrosoft.com" does not have CryptographicKey referenced by storageReferenceId "B2C_1A_x".`}
	var waits []time.Duration
	calls := 0
	err := recordingRetry(5*time.Second, &waits).do(context.Background(), func() error {
		calls++
		return notReady
	})
	if !errors.Is(err, notReady) {
		t.Fatalf("err = %v; want it to wrap the API error", err)
	}
	if ae := graphAPIError(err); ae != notReady {
		t.Errorf("graphAPIError = %v; want the API error", ae)
	}
	if !strings.Contains(err.Error(), "waited 3 seconds") || !strings.Contains(err.Error(), "may be wrong") {
		t.Errorf("err = %q; want the waited and may-be-wrong message", err)
	}
	if calls != 3 || len(waits) != 2 {
		t.Errorf("calls = %d, waits = %v; want 3 calls and waits of 1s and 2s", calls, waits)
	}
}

func TestDependencyRetryHonoursContext(t *testing.T) {
	notReady := &httpx.APIError{Status: http.StatusBadRequest, Body: "Policy with 'policyId': B2C_1A_BASE cannot be found in the directory"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var waits []time.Duration
	calls := 0
	err := recordingRetry(time.Minute, &waits).do(ctx, func() error {
		calls++
		return notReady
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, notReady) || calls != 1 {
		t.Errorf("err = %v, calls = %d; want canceled wrapping the API error after 1 call", err, calls)
	}
}

// testFastRetry retries without sleeping.
var testFastRetry = dependencyRetry{
	Timeout:   time.Second,
	BaseDelay: time.Millisecond,
	MaxDelay:  time.Millisecond,
	sleep:     func(context.Context, time.Duration) error { return nil },
}
