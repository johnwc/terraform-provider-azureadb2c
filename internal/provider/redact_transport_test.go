package provider

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const redactMarker = "marker-secret-value"

func newRedactTestServer(t *testing.T, got *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func doRedactPost(t *testing.T, tr http.RoundTripper, url, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()
}

func TestSecretRedactingDebugTransportRedactsUploadSecret(t *testing.T) {
	t.Setenv("MSADMIN_HTTP_DEBUG", "1")
	var received string
	srv := newRedactTestServer(t, &received)
	var out bytes.Buffer
	tr := &secretRedactingDebugTransport{Out: &out}

	body := `{"use":"sig","k":"` + redactMarker + `"}`
	doRedactPost(t, tr, srv.URL+"/trustFramework/keySets/B2C_1A_x/UploadSecret", body)

	if received != body {
		t.Errorf("server received %q; want %q", received, body)
	}
	if strings.Contains(out.String(), redactMarker) {
		t.Errorf("log contains the secret: %s", out.String())
	}
	if !strings.Contains(out.String(), "(body redacted)") || !strings.Contains(out.String(), "204") {
		t.Errorf("log = %q; want a redaction note and the status", out.String())
	}
}

func TestSecretRedactingDebugTransportLogsOtherBodies(t *testing.T) {
	t.Setenv("MSADMIN_HTTP_DEBUG", "1")
	var received string
	srv := newRedactTestServer(t, &received)
	var out bytes.Buffer
	tr := &secretRedactingDebugTransport{Out: &out}

	doRedactPost(t, tr, srv.URL+"/trustFramework/keySets", `{"id":"B2C_1A_x"}`)

	if received != `{"id":"B2C_1A_x"}` {
		t.Errorf("server received %q", received)
	}
	if !strings.Contains(out.String(), "body: "+`{"id":"B2C_1A_x"}`) {
		t.Errorf("log = %q; want the request body", out.String())
	}
}

func TestSecretRedactingDebugTransportSilentWhenDebugOff(t *testing.T) {
	t.Setenv("MSADMIN_HTTP_DEBUG", "")
	t.Setenv("TF_LOG", "")
	t.Setenv("TF_LOG_PROVIDER", "")
	var received string
	srv := newRedactTestServer(t, &received)
	var out bytes.Buffer
	tr := &secretRedactingDebugTransport{Out: &out}

	doRedactPost(t, tr, srv.URL+"/trustFramework/keySets/B2C_1A_x/uploadSecret", `{"k":"`+redactMarker+`"}`)
	doRedactPost(t, tr, srv.URL+"/trustFramework/keySets", `{}`)

	if out.Len() != 0 {
		t.Errorf("log = %q; want nothing", out.String())
	}
	if received != `{}` {
		t.Errorf("server received %q", received)
	}
}
