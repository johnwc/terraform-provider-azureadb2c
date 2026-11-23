package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/terraprovider/go-msadmin/auth"
	"github.com/terraprovider/go-msadmin/httpx"
)

// graphBaseURL is the Microsoft Graph endpoint. The trustFramework API is beta-only.
const graphBaseURL = "https://graph.microsoft.com/beta"

// graphResource is the token audience for Microsoft Graph.
const graphResource = "https://graph.microsoft.com"

// graphBodyMax is the longest response body excerpt kept in an error.
const graphBodyMax = 600

// Content types of Graph request bodies.
const (
	contentTypeJSON = "application/json"
	contentTypeXML  = "application/xml"
)

// graphClient is the configured Microsoft Graph client shared by all resources
// and data sources.
type graphClient struct {
	Tokens  auth.TokenProvider // token source for Microsoft Graph
	HTTP    *http.Client       // HTTP client (retry + debug transports)
	BaseURL string             // Graph base URL; empty means graphBaseURL
}

// baseURL returns the Graph base URL without a trailing slash.
func (c *graphClient) baseURL() string {
	if c.BaseURL == "" {
		return graphBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

// graphDo sends one Microsoft Graph JSON request and returns the response body.
// A non-2xx response is returned as an *httpx.APIError.
func graphDo(ctx context.Context, c *graphClient, method, path string, body any) ([]byte, error) {
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return graphSend(ctx, c, method, path, raw, contentTypeJSON, contentTypeJSON)
}

// graphDoXML sends one Microsoft Graph request with a raw XML body (nil for
// none) and returns the raw response body. A non-2xx response is returned as an
// *httpx.APIError.
func graphDoXML(ctx context.Context, c *graphClient, method, path string, body []byte) ([]byte, error) {
	return graphSend(ctx, c, method, path, body, contentTypeXML, "")
}

// graphSend sends one request. contentType is set only when body is non-nil;
// accept is set only when non-empty.
func graphSend(ctx context.Context, c *graphClient, method, path string, body []byte, contentType, accept string) ([]byte, error) {
	if c == nil || c.Tokens == nil {
		return nil, fmt.Errorf("microsoft graph: the provider has no token source")
	}
	if c.HTTP == nil {
		return nil, fmt.Errorf("microsoft graph: the provider has no HTTP client")
	}
	token, err := c.Tokens.Token(ctx, graphResource)
	if err != nil {
		return nil, fmt.Errorf("microsoft graph: token: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	raw, err := httpx.DecodeBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, graphError(method, path, resp.StatusCode, raw)
	}
	return raw, nil
}

// graphError builds the error for a non-2xx Graph response.
func graphError(method, path string, status int, raw []byte) error {
	code := ""
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil {
		code = env.Error.Code
	}
	excerpt := strings.TrimSpace(string(raw))
	if len(excerpt) > graphBodyMax {
		cut := graphBodyMax
		for cut > 0 && !utf8.RuneStart(excerpt[cut]) {
			cut--
		}
		excerpt = excerpt[:cut]
	}
	if excerpt == "" {
		excerpt = "(no response body)"
	}
	msg := fmt.Sprintf("microsoft graph %s %s: %s", method, path, excerpt)
	if status == http.StatusForbidden {
		msg += " — the app may need the Microsoft Graph application permissions Policy.ReadWrite.TrustFramework and TrustFrameworkKeySet.ReadWrite.All with admin consent"
	}
	return &httpx.APIError{Status: status, Code: code, Message: msg, Body: excerpt}
}

// graphAPIError returns the *httpx.APIError in err, or nil.
func graphAPIError(err error) *httpx.APIError {
	var ae *httpx.APIError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}

// isGraphNotFound reports whether err is a Graph 404.
func isGraphNotFound(err error) bool { return httpx.IsNotFound(err) }

// b2cNotFoundCode is the B2C error code for an object that does not exist.
const b2cNotFoundCode = "AADB2C90073"

// isKeySetNotFound reports whether err says a key set does not exist: a Graph
// 404, or the 400 carrying the B2C not-found code that a key set read returns.
func isKeySetNotFound(err error) bool {
	if isGraphNotFound(err) {
		return true
	}
	ae := graphAPIError(err)
	return ae != nil && ae.Status == http.StatusBadRequest && ae.Code == b2cNotFoundCode
}

// isGraphConflict reports whether err says the object already exists: a 409, or
// a 400 whose body says "already exists".
func isGraphConflict(err error) bool {
	ae := graphAPIError(err)
	if ae == nil {
		return false
	}
	if ae.Status == http.StatusConflict {
		return true
	}
	return ae.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(ae.Body), "already exists")
}
