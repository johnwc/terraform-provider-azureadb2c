package provider

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/terraprovider/go-msadmin/httpx"
)

// secretUploadSuffix is the path suffix of the key set upload endpoint, whose
// request body carries the secret.
const secretUploadSuffix = "/uploadsecret"

// secretRedactingDebugTransport is an http.RoundTripper that logs requests like
// httpx.DebugTransport, except that requests to an uploadSecret endpoint are
// sent without their body being logged.
type secretRedactingDebugTransport struct {
	Base http.RoundTripper // nil -> http.DefaultTransport
	Out  io.Writer         // nil -> os.Stderr
}

// newSecretRedactingDebugTransport wraps base (nil -> http.DefaultTransport).
func newSecretRedactingDebugTransport(base http.RoundTripper) *secretRedactingDebugTransport {
	return &secretRedactingDebugTransport{Base: base}
}

func (t *secretRedactingDebugTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *secretRedactingDebugTransport) out() io.Writer {
	if t.Out != nil {
		return t.Out
	}
	return os.Stderr
}

// RoundTrip implements http.RoundTripper.
func (t *secretRedactingDebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !httpx.DebugEnabled() || !strings.HasSuffix(strings.ToLower(req.URL.Path), secretUploadSuffix) {
		return (&httpx.DebugTransport{Base: t.base(), Out: t.Out}).RoundTrip(req)
	}

	out := t.out()
	fmt.Fprintf(out, "[http] >>> %s %s (body redacted)\n", req.Method, req.URL.String())
	resp, err := t.base().RoundTrip(req)
	if err != nil {
		fmt.Fprintf(out, "[http] <<< transport error: %v\n", err)
		return resp, err
	}
	fmt.Fprintf(out, "[http] <<< %s\n", resp.Status)
	return resp, nil
}
