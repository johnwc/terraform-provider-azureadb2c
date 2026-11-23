package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/terraprovider/go-msadmin/auth"
	"github.com/terraprovider/go-msadmin/httpx"
)

// fakeResponse is one canned reply of a fakeGraph.
type fakeResponse struct {
	status int
	body   string
}

// recordedRequest is one request a fakeGraph received.
type recordedRequest struct {
	Method      string
	Path        string // escaped path, e.g. /trustFramework/policies/B2C_1A_x/$value
	ContentType string
	Accept      string
	Auth        string
	Body        string
}

// fakeGraph is an httptest.Server answering "<METHOD> <path>" with queued
// responses (the last one repeats) and recording every request.
type fakeGraph struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	responses map[string][]fakeResponse
	requests  []recordedRequest
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	f := &fakeGraph{t: t, responses: map[string][]fakeResponse{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// on queues a response for "<METHOD> <path>".
func (f *fakeGraph) on(method, path string, status int, body string) *fakeGraph {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := method + " " + path
	f.responses[key] = append(f.responses[key], fakeResponse{status: status, body: body})
	return f
}

func (f *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	p := r.URL.EscapedPath()
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{
		Method: r.Method, Path: p, ContentType: r.Header.Get("Content-Type"),
		Accept: r.Header.Get("Accept"), Auth: r.Header.Get("Authorization"), Body: string(b),
	})
	key := r.Method + " " + p
	queue := f.responses[key]
	var resp fakeResponse
	switch {
	case len(queue) == 0:
		resp = fakeResponse{status: http.StatusInternalServerError, body: `{"error":{"code":"unexpected","message":"unexpected call ` + key + `"}}`}
	case len(queue) == 1:
		resp = queue[0]
	default:
		resp = queue[0]
		f.responses[key] = queue[1:]
	}
	f.mu.Unlock()
	w.WriteHeader(resp.status)
	_, _ = io.WriteString(w, resp.body)
}

// calls returns the recorded requests as "<METHOD> <path>".
func (f *fakeGraph) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.requests))
	for _, r := range f.requests {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

// request returns the i-th recorded request.
func (f *fakeGraph) request(i int) recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.requests) {
		f.t.Fatalf("only %d requests recorded, want #%d", len(f.requests), i)
	}
	return f.requests[i]
}

// client returns a graphClient pointed at the fake. It uses the server's plain
// HTTP client (no retry transport) so a canned 500 is not retried.
func (f *fakeGraph) client() *graphClient {
	return &graphClient{Tokens: auth.StaticToken("tok"), HTTP: f.srv.Client(), BaseURL: f.srv.URL}
}

// tokenRecorder records the resource it was asked for.
type tokenRecorder struct{ resource string }

func (t *tokenRecorder) Token(_ context.Context, resource string) (string, error) {
	t.resource = resource
	return "tok", nil
}

func TestGraphDoJSON(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"B2C_1A_x","keys":[]}`)
	c := f.client()
	tp := &tokenRecorder{}
	c.Tokens = tp
	raw, err := graphDo(context.Background(), c, http.MethodPost, "/trustFramework/keySets", map[string]any{"id": "B2C_1A_x"})
	if err != nil {
		t.Fatalf("graphDo: %v", err)
	}
	if !strings.Contains(string(raw), `"B2C_1A_x"`) {
		t.Errorf("body = %s", raw)
	}
	r := f.request(0)
	if r.ContentType != "application/json" || r.Accept != "application/json" {
		t.Errorf("Content-Type = %q, Accept = %q", r.ContentType, r.Accept)
	}
	if r.Auth != "Bearer tok" {
		t.Errorf("Authorization = %q", r.Auth)
	}
	if tp.resource != "https://graph.microsoft.com" {
		t.Errorf("token resource = %q", tp.resource)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(r.Body), &sent); err != nil || sent["id"] != "B2C_1A_x" {
		t.Errorf("sent = %q", r.Body)
	}
}

func TestGraphDoJSONNoBody(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodDelete, "/trustFramework/keySets/B2C_1A_x", http.StatusNoContent, "")
	if _, err := graphDo(context.Background(), f.client(), http.MethodDelete, "/trustFramework/keySets/B2C_1A_x", nil); err != nil {
		t.Fatalf("graphDo: %v", err)
	}
	if r := f.request(0); r.ContentType != "" || r.Body != "" {
		t.Errorf("Content-Type = %q, body = %q; want none", r.ContentType, r.Body)
	}
}

func TestGraphDoXML(t *testing.T) {
	const doc = `<TrustFrameworkPolicy PolicyId="B2C_1A_x"/>`
	f := newFakeGraph(t).
		on(http.MethodPut, "/trustFramework/policies/B2C_1A_x/$value", http.StatusOK, "").
		on(http.MethodGet, "/trustFramework/policies/B2C_1A_x/$value", http.StatusOK, doc)
	c := f.client()
	if _, err := graphDoXML(context.Background(), c, http.MethodPut, "/trustFramework/policies/B2C_1A_x/$value", []byte(doc)); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	r := f.request(0)
	if r.ContentType != "application/xml" || r.Body != doc {
		t.Errorf("Content-Type = %q, body = %q", r.ContentType, r.Body)
	}
	raw, err := graphDoXML(context.Background(), c, http.MethodGet, "/trustFramework/policies/B2C_1A_x/$value", nil)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if string(raw) != doc {
		t.Errorf("GET body = %q", raw)
	}
	if r := f.request(1); r.ContentType != "" || r.Body != "" {
		t.Errorf("GET sent Content-Type %q and body %q", r.ContentType, r.Body)
	}
}

func TestGraphDoErrorMapping(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodGet, "/trustFramework/policies/B2C_1A_missing/$value", http.StatusNotFound,
			`{"error":{"code":"AADB2C90181","message":"Policy 'B2C_1A_missing' does not exist."}}`).
		on(http.MethodGet, "/trustFramework/keySets/B2C_1A_x", http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusConflict, `{"error":{"code":"Conflict","message":"Key set already exists."}}`)
	c := f.client()

	_, err := graphDoXML(context.Background(), c, http.MethodGet, "/trustFramework/policies/B2C_1A_missing/$value", nil)
	if !isGraphNotFound(err) {
		t.Fatalf("isGraphNotFound(%v) = false", err)
	}
	var ae *httpx.APIError
	if !errors.As(err, &ae) || ae.Code != "AADB2C90181" || ae.Status != http.StatusNotFound {
		t.Errorf("err = %#v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "404") || !strings.Contains(msg, "does not exist") || !strings.Contains(msg, "GET /trustFramework/policies/B2C_1A_missing/$value") {
		t.Errorf("message = %q; want method, path, status and body excerpt", msg)
	}

	_, err = graphDo(context.Background(), c, http.MethodGet, "/trustFramework/keySets/B2C_1A_x", nil)
	if isGraphNotFound(err) || !strings.Contains(err.Error(), "TrustFrameworkKeySet.ReadWrite.All") {
		t.Errorf("403 error = %v; want a permissions hint", err)
	}

	_, err = graphDo(context.Background(), c, http.MethodPost, "/trustFramework/keySets", map[string]any{"id": "B2C_1A_x"})
	if !isGraphConflict(err) {
		t.Errorf("isGraphConflict(%v) = false", err)
	}
}

func TestGraphError(t *testing.T) {
	long := graphError(http.MethodGet, "/x", http.StatusInternalServerError, []byte(strings.Repeat("a", 2000)))
	if isGraphNotFound(long) {
		t.Error("500 reported as not found")
	}
	var ae *httpx.APIError
	if !errors.As(long, &ae) || len(ae.Body) != graphBodyMax {
		t.Errorf("excerpt = %#v; want %d bytes", long, graphBodyMax)
	}
	if isGraphNotFound(errors.New("plain")) || isGraphNotFound(nil) {
		t.Error("non-API errors reported as not found")
	}
	empty := graphError(http.MethodGet, "/x", http.StatusBadRequest, nil)
	if !errors.As(empty, &ae) || ae.Body != "(no response body)" {
		t.Errorf("empty body = %#v", empty)
	}
}

func TestGraphErrorTruncatesOnRuneBoundary(t *testing.T) {
	body := "a" + strings.Repeat("é", graphBodyMax)
	err := graphError(http.MethodGet, "/x", http.StatusInternalServerError, []byte(body))
	var ae *httpx.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %#v", err)
	}
	if !utf8.ValidString(ae.Body) || len(ae.Body) > graphBodyMax {
		t.Errorf("excerpt has %d bytes, valid UTF-8 = %v", len(ae.Body), utf8.ValidString(ae.Body))
	}
}

func TestIsGraphConflict(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"409", &httpx.APIError{Status: http.StatusConflict}, true},
		{"400 already exists", &httpx.APIError{Status: http.StatusBadRequest, Body: `{"error":{"message":"A policy with this id Already Exists."}}`}, true},
		{"400 other", &httpx.APIError{Status: http.StatusBadRequest, Body: "invalid XML"}, false},
		{"404", &httpx.APIError{Status: http.StatusNotFound, Body: "already exists"}, false},
		{"plain", errors.New("409"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := isGraphConflict(tc.err); got != tc.want {
			t.Errorf("%s: isGraphConflict = %v; want %v", tc.name, got, tc.want)
		}
	}
}

func TestGraphNoTokens(t *testing.T) {
	if _, err := graphDo(context.Background(), &graphClient{}, http.MethodGet, "/x", nil); err == nil {
		t.Error("expected an error without a token source")
	}
	if _, err := graphDo(context.Background(), nil, http.MethodGet, "/x", nil); err == nil {
		t.Error("expected an error without a client")
	}
}

func TestGraphNoHTTPClient(t *testing.T) {
	c := &graphClient{Tokens: auth.StaticToken("tok")}
	if _, err := graphDo(context.Background(), c, http.MethodGet, "/x", nil); err == nil {
		t.Error("expected an error without an HTTP client")
	}
}

func TestGraphBaseURL(t *testing.T) {
	if got := (&graphClient{}).baseURL(); got != "https://graph.microsoft.com/beta" {
		t.Errorf("default base URL = %q", got)
	}
	if got := (&graphClient{BaseURL: "http://127.0.0.1:1234/"}).baseURL(); got != "http://127.0.0.1:1234" {
		t.Errorf("base URL = %q", got)
	}
}

func TestIsKeySetNotFound(t *testing.T) {
	missing := graphError(http.MethodGet, "/trustFramework/keySets/B2C_1A_x", http.StatusBadRequest, []byte(`{"error":{"code":"AADB2C90073","message":"KeyContainer with 'id': 'B2C_1A_x' cannot be found in the directory 'contoso.onmicrosoft.com'."}}`))
	if !isKeySetNotFound(missing) {
		t.Error("a 400 with the B2C not-found code should count as a missing key set")
	}
	if isGraphNotFound(missing) {
		t.Error("the 400 is a not-found for key sets only")
	}
	if !isKeySetNotFound(graphError(http.MethodDelete, "/trustFramework/keySets/B2C_1A_x", http.StatusNotFound, nil)) {
		t.Error("a 404 should count as a missing key set")
	}
	other := graphError(http.MethodPost, "/trustFramework/keySets", http.StatusBadRequest, []byte(`{"error":{"code":"AADB2C90293","message":"invalid id"}}`))
	if isKeySetNotFound(other) {
		t.Error("any other 400 is not a not-found")
	}
}
