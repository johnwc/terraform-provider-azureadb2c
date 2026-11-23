package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const testKeySetID = "B2C_1A_TfTest"

func int64p(v int64) *int64 { return &v }
func strp(v string) *string { return &v }

func decodeSent(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("request body %q: %v", body, err)
	}
	return m
}

func TestCreateKeySetGenerate(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`","keys":[]}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/generateKey", http.StatusOK, `{"kid":"kid-1","use":"sig","kty":"RSA","nbf":1700000000,"exp":1800000000}`)
	key, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "RSA", NotBefore: int64p(1700000000), Expires: int64p(1800000000)})
	if err != nil {
		t.Fatalf("createKeySet: %v", err)
	}
	if key.Kid != "kid-1" {
		t.Errorf("key = %+v", key)
	}
	want := []string{"POST /trustFramework/keySets", "POST /trustFramework/keySets/" + testKeySetID + "/generateKey"}
	if got := f.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q", got)
	}
	if got := decodeSent(t, f.request(0).Body); !reflect.DeepEqual(got, map[string]any{"id": testKeySetID}) {
		t.Errorf("create body = %v", got)
	}
	got := decodeSent(t, f.request(1).Body)
	wantBody := map[string]any{"use": "sig", "kty": "RSA", "nbf": float64(1700000000), "exp": float64(1800000000)}
	if !reflect.DeepEqual(got, wantBody) {
		t.Errorf("generateKey body = %v; want %v", got, wantBody)
	}
}

func TestCreateKeySetUploadSecret(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/uploadSecret", http.StatusOK, `{"kid":"kid-2","use":"enc","kty":"oct"}`)
	key, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "enc", KeyType: "oct", Secret: strp("s3cret")})
	if err != nil {
		t.Fatalf("createKeySet: %v", err)
	}
	if key.Kid != "kid-2" {
		t.Errorf("key = %+v", key)
	}
	got := decodeSent(t, f.request(1).Body)
	if !reflect.DeepEqual(got, map[string]any{"use": "enc", "k": "s3cret"}) {
		t.Errorf("uploadSecret body = %v", got)
	}
}

func TestCreateKeySetCleansUpOnFailure(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/uploadSecret", http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"The secret is too short."}}`).
		on(http.MethodDelete, "/trustFramework/keySets/"+testKeySetID, http.StatusNoContent, "")
	_, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "oct", Secret: strp("x")})
	if err == nil || !strings.Contains(err.Error(), "too short") || !strings.Contains(err.Error(), "was removed") {
		t.Fatalf("err = %v; want the upload error and a note that the key set was removed", err)
	}
	want := []string{
		"POST /trustFramework/keySets",
		"POST /trustFramework/keySets/" + testKeySetID + "/uploadSecret",
		"DELETE /trustFramework/keySets/" + testKeySetID,
	}
	if got := f.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q\nwant %q", got, want)
	}
	if graphAPIError(err) == nil || graphAPIError(err).Status != http.StatusBadRequest {
		t.Errorf("the upload APIError should be wrapped: %#v", err)
	}
}

// cancelOnTokenCall cancels a context when its n-th token is requested, so the
// request that asked for it fails with a cancelled context.
type cancelOnTokenCall struct {
	n      int
	calls  int
	cancel context.CancelFunc
}

func (c *cancelOnTokenCall) Token(context.Context, string) (string, error) {
	c.calls++
	if c.calls == c.n {
		c.cancel()
	}
	return "tok", nil
}

func TestCreateKeySetCleanupSurvivesCancelledContext(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodDelete, "/trustFramework/keySets/"+testKeySetID, http.StatusNoContent, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := f.client()
	c.Tokens = &cancelOnTokenCall{n: 2, cancel: cancel}
	_, err := createKeySet(ctx, c, keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "oct", Secret: strp("x")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want the cancelled upload", err)
	}
	if !strings.Contains(err.Error(), "was removed") {
		t.Errorf("err = %v; want a note that the key set was removed", err)
	}
	want := []string{"POST /trustFramework/keySets", "DELETE /trustFramework/keySets/" + testKeySetID}
	if got := f.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q\nwant %q", got, want)
	}
}

func TestCreateKeySetUndecodableResponseIsNotAFailure(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/generateKey", http.StatusOK, `not json`)
	key, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "RSA"})
	if err != nil {
		t.Fatalf("createKeySet: %v", err)
	}
	if key != (trustFrameworkKey{}) {
		t.Errorf("key = %+v; want empty", key)
	}
	want := []string{"POST /trustFramework/keySets", "POST /trustFramework/keySets/" + testKeySetID + "/generateKey"}
	if got := f.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q; the key set must not be deleted\nwant %q", got, want)
	}
}

func TestCreateKeySetCleanupFailureIsReported(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/generateKey", http.StatusBadRequest, `{"error":{"code":"x","message":"bad kty"}}`).
		on(http.MethodDelete, "/trustFramework/keySets/"+testKeySetID, http.StatusForbidden, `{"error":{"code":"x","message":"denied"}}`)
	_, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "RSA"})
	if err == nil || !strings.Contains(err.Error(), "bad kty") || !strings.Contains(err.Error(), "also failed") {
		t.Errorf("err = %v; want both errors", err)
	}
}

func TestCreateKeySetConflict(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/keySets", http.StatusConflict, `{"error":{"code":"Conflict","message":"exists"}}`)
	_, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "RSA"})
	if !errors.Is(err, errKeySetExists) {
		t.Errorf("err = %v; want errKeySetExists", err)
	}
	if !isGraphConflict(err) {
		t.Error("the conflict APIError should be wrapped")
	}
	if n := len(f.calls()); n != 1 {
		t.Errorf("calls = %d; a conflict must not delete the existing key set", n)
	}
}

func TestCreateKeySetOtherCreateError(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/keySets", http.StatusForbidden, `{"error":{"code":"x","message":"denied"}}`)
	_, err := createKeySet(context.Background(), f.client(), keySetSpec{ID: testKeySetID, Use: "sig", KeyType: "RSA"})
	if err == nil || errors.Is(err, errKeySetExists) {
		t.Errorf("err = %v", err)
	}
	if n := len(f.calls()); n != 1 {
		t.Errorf("calls = %d; want 1", n)
	}
}

func TestReadAndDeleteKeySet(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodGet, "/trustFramework/keySets/"+testKeySetID, http.StatusOK, `{"id":"`+testKeySetID+`","keys":[{"kid":"kid-1","use":"sig","kty":"RSA","nbf":1,"exp":2}]}`).
		on(http.MethodDelete, "/trustFramework/keySets/"+testKeySetID, http.StatusNotFound, `{"error":{"code":"x","message":"gone"}}`)
	ks, err := readKeySet(context.Background(), f.client(), testKeySetID)
	if err != nil {
		t.Fatalf("readKeySet: %v", err)
	}
	if k := selectKey(ks, "", time.Now()); k == nil || k.Kid != "kid-1" || *k.Nbf != 1 || *k.Exp != 2 {
		t.Errorf("key set = %+v", ks)
	}
	if err := deleteKeySet(context.Background(), f.client(), testKeySetID); err != nil {
		t.Errorf("deleteKeySet of a missing key set: %v", err)
	}
}

func TestKeySetStateFromServer(t *testing.T) {
	ks := trustFrameworkKeySet{ID: testKeySetID, Keys: []trustFrameworkKey{{Kid: "kid-1", Use: "SIG", Kty: "rsa", Nbf: int64p(10), Exp: int64p(20)}}}

	// Configured values that differ only in case are kept; null dates stay null.
	m := trustFrameworkKeySetModel{
		ID: types.StringValue(testKeySetID), Use: types.StringValue("sig"), KeyType: types.StringValue("RSA"),
		Secret: types.StringNull(), SecretWO: types.StringNull(), SecretWOVersion: types.Int64Null(),
		NotBefore: types.Int64Null(), Expires: types.Int64Null(), KeyID: types.StringNull(),
	}
	now := time.Unix(100, 0)
	keySetStateFromServer(&m, ks, now)
	if m.Use.ValueString() != "sig" || m.KeyType.ValueString() != "RSA" || m.KeyID.ValueString() != "kid-1" {
		t.Errorf("model = %+v", m)
	}
	if !m.NotBefore.IsNull() || !m.Expires.IsNull() {
		t.Errorf("null dates were overwritten: %+v", m)
	}

	// Dates set in state are refreshed.
	m.NotBefore, m.Expires = types.Int64Value(1), types.Int64Value(2)
	keySetStateFromServer(&m, ks, now)
	if m.NotBefore.ValueInt64() != 10 || m.Expires.ValueInt64() != 20 {
		t.Errorf("dates = %v / %v; want 10 / 20", m.NotBefore, m.Expires)
	}

	// Import: use and key_type come from the server, normalised; the secret stays null.
	imported := trustFrameworkKeySetModel{
		ID: types.StringValue(testKeySetID), Use: types.StringNull(), KeyType: types.StringNull(),
		Secret: types.StringNull(), SecretWO: types.StringNull(), SecretWOVersion: types.Int64Null(),
		NotBefore: types.Int64Null(), Expires: types.Int64Null(), KeyID: types.StringNull(),
	}
	keySetStateFromServer(&imported, ks, now)
	if imported.Use.ValueString() != "sig" || imported.KeyType.ValueString() != "RSA" || !imported.Secret.IsNull() {
		t.Errorf("imported = %+v", imported)
	}

	// A changed use is picked up as drift.
	m.Use = types.StringValue("enc")
	keySetStateFromServer(&m, ks, now)
	if m.Use.ValueString() != "sig" {
		t.Errorf("use = %s; want sig from the server", m.Use)
	}

	// No keys: key_id is null.
	keySetStateFromServer(&m, trustFrameworkKeySet{ID: testKeySetID}, now)
	if !m.KeyID.IsNull() {
		t.Errorf("key_id = %s; want null", m.KeyID)
	}
}

func TestKeySetStateFromServerPrefersKeyIDInState(t *testing.T) {
	ks := trustFrameworkKeySet{ID: testKeySetID, Keys: []trustFrameworkKey{
		{Kid: "new", Use: "sig", Kty: "RSA", Nbf: int64p(50)},
		{Kid: "old", Use: "sig", Kty: "RSA", Nbf: int64p(10)},
	}}
	m := trustFrameworkKeySetModel{
		ID: types.StringValue(testKeySetID), Use: types.StringValue("sig"), KeyType: types.StringValue("RSA"),
		Secret: types.StringNull(), SecretWO: types.StringNull(), SecretWOVersion: types.Int64Null(),
		NotBefore: types.Int64Value(10), Expires: types.Int64Null(), KeyID: types.StringValue("old"),
	}
	keySetStateFromServer(&m, ks, time.Unix(100, 0))
	if m.KeyID.ValueString() != "old" || m.NotBefore.ValueInt64() != 10 {
		t.Errorf("key_id = %s, not_before = %s; want the key from state", m.KeyID, m.NotBefore)
	}
}

func TestSelectKey(t *testing.T) {
	now := time.Unix(100, 0)
	a := trustFrameworkKey{Kid: "a", Nbf: int64p(10)}
	b := trustFrameworkKey{Kid: "b", Nbf: int64p(90)}
	future := trustFrameworkKey{Kid: "future", Nbf: int64p(500)}
	noNbf := trustFrameworkKey{Kid: "none"}
	cases := []struct {
		name string
		keys []trustFrameworkKey
		kid  string
		want string // "" for nil
	}{
		{"empty", nil, "", ""},
		{"empty with known kid", nil, "a", ""},
		{"single", []trustFrameworkKey{a}, "", "a"},
		{"single in the future", []trustFrameworkKey{future}, "", "future"},
		{"kid match wins over a later nbf", []trustFrameworkKey{b, a}, "a", "a"},
		{"kid match wins over a future key", []trustFrameworkKey{future, a}, "future", "future"},
		{"unknown kid falls back to nbf", []trustFrameworkKey{a, b}, "gone", "b"},
		{"latest valid nbf wins", []trustFrameworkKey{a, b}, "", "b"},
		{"latest valid nbf wins in any order", []trustFrameworkKey{b, a}, "", "b"},
		{"future key is skipped", []trustFrameworkKey{future, a}, "", "a"},
		{"missing nbf counts as 0", []trustFrameworkKey{noNbf, a}, "", "a"},
		{"missing nbf is valid", []trustFrameworkKey{future, noNbf}, "", "none"},
		{"all in the future falls back to the first", []trustFrameworkKey{future, {Kid: "later", Nbf: int64p(900)}}, "", "future"},
		{"equal nbf keeps the first", []trustFrameworkKey{{Kid: "x", Nbf: int64p(10)}, {Kid: "y", Nbf: int64p(10)}}, "", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectKey(trustFrameworkKeySet{Keys: tc.keys}, tc.kid, now)
			switch {
			case tc.want == "" && got != nil:
				t.Errorf("selectKey = %+v; want nil", got)
			case tc.want != "" && (got == nil || got.Kid != tc.want):
				t.Errorf("selectKey = %+v; want %s", got, tc.want)
			}
		})
	}
}

func TestKeySetDataFromServer(t *testing.T) {
	now := time.Unix(100, 0)
	use, kty, kid := keySetDataFromServer(trustFrameworkKeySet{Keys: []trustFrameworkKey{{Kid: "k", Use: "enc", Kty: "OCT"}}}, now)
	if use.ValueString() != "enc" || kty.ValueString() != "oct" || kid.ValueString() != "k" {
		t.Errorf("got %s %s %s", use, kty, kid)
	}
	use, kty, kid = keySetDataFromServer(trustFrameworkKeySet{}, now)
	if !use.IsNull() || !kty.IsNull() || !kid.IsNull() {
		t.Errorf("empty key set: got %s %s %s", use, kty, kid)
	}
}

func TestValidateKeySet(t *testing.T) {
	base := func() trustFrameworkKeySetModel {
		return trustFrameworkKeySetModel{
			ID: types.StringValue(testKeySetID), Use: types.StringValue("sig"), KeyType: types.StringValue("oct"),
			Secret: types.StringNull(), SecretWO: types.StringNull(), SecretWOVersion: types.Int64Null(),
			NotBefore: types.Int64Null(), Expires: types.Int64Null(), KeyID: types.StringUnknown(),
		}
	}
	cases := []struct {
		name    string
		mutate  func(m *trustFrameworkKeySetModel)
		wantErr string // "" for valid
	}{
		{"generate oct", func(m *trustFrameworkKeySetModel) {}, ""},
		{"generate RSA", func(m *trustFrameworkKeySetModel) { m.KeyType = types.StringValue("rsa") }, ""},
		{"upload secret", func(m *trustFrameworkKeySetModel) { m.Secret = types.StringValue("s") }, ""},
		{"write-only secret with version", func(m *trustFrameworkKeySetModel) {
			m.SecretWO, m.SecretWOVersion = types.StringValue("s"), types.Int64Value(1)
		}, ""},
		{"unknown values", func(m *trustFrameworkKeySetModel) {
			m.ID, m.Use, m.KeyType, m.Secret = types.StringUnknown(), types.StringUnknown(), types.StringUnknown(), types.StringUnknown()
		}, ""},
		{"lowercase prefix", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("b2c_1a_x") }, ""},
		{"missing prefix", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("TokenSigningKeyContainer") }, "Invalid key set id"},
		{"underscore after prefix", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("B2C_1A_tf_acc") }, "Invalid key set id"},
		{"nothing after prefix", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("B2C_1A_") }, "Invalid key set id"},
		{"non-ASCII letter", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("B2C_1A_Café") }, "Invalid key set id"},
		{"mixed case and digits", func(m *trustFrameworkKeySetModel) { m.ID = types.StringValue("B2C_1A_TokenSigning2Key") }, ""},
		{"bad use", func(m *trustFrameworkKeySetModel) { m.Use = types.StringValue("sign") }, "Invalid key use"},
		{"bad key type", func(m *trustFrameworkKeySetModel) { m.KeyType = types.StringValue("EC") }, "Invalid key type"},
		{"both secrets", func(m *trustFrameworkKeySetModel) {
			m.Secret, m.SecretWO = types.StringValue("a"), types.StringValue("b")
		}, "Conflicting secrets"},
		{"unknown secret with write-only secret", func(m *trustFrameworkKeySetModel) {
			m.Secret, m.SecretWO = types.StringUnknown(), types.StringValue("b")
		}, "Conflicting secrets"},
		{"version without write-only secret", func(m *trustFrameworkKeySetModel) { m.SecretWOVersion = types.Int64Value(1) }, "Missing secret_wo"},
		{"secret with RSA", func(m *trustFrameworkKeySetModel) {
			m.KeyType, m.Secret = types.StringValue("RSA"), types.StringValue("s")
		}, "Secret needs key_type oct"},
		{"write-only secret with RSA", func(m *trustFrameworkKeySetModel) {
			m.KeyType, m.SecretWO = types.StringValue("RSA"), types.StringValue("s")
		}, "Secret needs key_type oct"},
		{"expires before not_before", func(m *trustFrameworkKeySetModel) {
			m.NotBefore, m.Expires = types.Int64Value(20), types.Int64Value(10)
		}, "Invalid expiry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(&m)
			d := validateKeySet(&m)
			if tc.wantErr == "" {
				if d.HasError() {
					t.Errorf("diagnostics = %v; want none", d)
				}
				return
			}
			if len(d.Errors()) != 1 || d.Errors()[0].Summary() != tc.wantErr {
				t.Errorf("diagnostics = %v; want one %q", d, tc.wantErr)
			}
		})
	}
}

func TestKeySetSpecFromModel(t *testing.T) {
	m := trustFrameworkKeySetModel{
		ID: types.StringValue(testKeySetID), Use: types.StringValue("SIG"), KeyType: types.StringValue("Oct"),
		Secret: types.StringNull(), SecretWO: types.StringValue("wo"), SecretWOVersion: types.Int64Value(1),
		NotBefore: types.Int64Value(5), Expires: types.Int64Null(), KeyID: types.StringUnknown(),
	}
	s := keySetSpecFromModel(&m)
	if s.ID != testKeySetID || s.Use != "sig" || s.KeyType != "oct" || s.Secret == nil || *s.Secret != "wo" || s.NotBefore == nil || *s.NotBefore != 5 || s.Expires != nil {
		t.Errorf("spec = %+v", s)
	}
	action, body := keyBody(s)
	if action != "uploadSecret" || !reflect.DeepEqual(body, map[string]any{"use": "sig", "k": "wo", "nbf": int64(5)}) {
		t.Errorf("keyBody = %s %v", action, body)
	}

	m.SecretWO = types.StringNull()
	m.KeyType = types.StringValue("rsa")
	action, body = keyBody(keySetSpecFromModel(&m))
	if action != "generateKey" || !reflect.DeepEqual(body, map[string]any{"use": "sig", "kty": "RSA", "nbf": int64(5)}) {
		t.Errorf("keyBody = %s %v", action, body)
	}
}

// keySetResourceSchema returns the key set resource schema.
func keySetResourceSchema(t *testing.T) (resource.SchemaResponse, tftypes.Object) {
	t.Helper()
	var sr resource.SchemaResponse
	(&trustFrameworkKeySetResource{}).Schema(context.Background(), resource.SchemaRequest{}, &sr)
	if sr.Diagnostics.HasError() {
		t.Fatalf("schema: %v", sr.Diagnostics)
	}
	return sr, sr.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
}

// keySetRaw builds a key set object value: every attribute null except overrides.
func keySetRaw(ot tftypes.Object, overrides map[string]tftypes.Value) tftypes.Value {
	vals := make(map[string]tftypes.Value, len(ot.AttributeTypes))
	for name, typ := range ot.AttributeTypes {
		vals[name] = tftypes.NewValue(typ, nil)
	}
	for name, v := range overrides {
		vals[name] = v
	}
	return tftypes.NewValue(ot, vals)
}

func TestKeySetCreateWriteOnlySecret(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/keySets", http.StatusCreated, `{"id":"`+testKeySetID+`"}`).
		on(http.MethodPost, "/trustFramework/keySets/"+testKeySetID+"/uploadSecret", http.StatusOK, `{"kid":"kid-wo","use":"enc","kty":"oct"}`)
	r := &trustFrameworkKeySetResource{client: f.client()}
	sr, ot := keySetResourceSchema(t)
	str := func(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }

	// The plan never holds a write-only value; the config does.
	plan := keySetRaw(ot, map[string]tftypes.Value{
		"id": str(testKeySetID), "use": str("enc"), "key_type": str("oct"),
		"secret_wo_version": tftypes.NewValue(tftypes.Number, 1),
		"key_id":            tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	})
	cfg := keySetRaw(ot, map[string]tftypes.Value{
		"id": str(testKeySetID), "use": str("enc"), "key_type": str("oct"),
		"secret_wo": str("wo-secret"), "secret_wo_version": tftypes.NewValue(tftypes.Number, 1),
	})
	req := resource.CreateRequest{
		Config: tfsdk.Config{Schema: sr.Schema, Raw: cfg},
		Plan:   tfsdk.Plan{Schema: sr.Schema, Raw: plan},
	}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(ot, nil)}}
	r.Create(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	if got := decodeSent(t, f.request(1).Body); !reflect.DeepEqual(got, map[string]any{"use": "enc", "k": "wo-secret"}) {
		t.Errorf("uploadSecret body = %v; want the write-only secret sent as k", got)
	}
	var secretWO, keyID types.String
	resp.Diagnostics.Append(resp.State.GetAttribute(context.Background(), path.Root("secret_wo"), &secretWO)...)
	resp.Diagnostics.Append(resp.State.GetAttribute(context.Background(), path.Root("key_id"), &keyID)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("reading state: %v", resp.Diagnostics)
	}
	if !secretWO.IsNull() {
		t.Errorf("state secret_wo = %s; want null", secretWO)
	}
	if keyID.ValueString() != "kid-wo" {
		t.Errorf("state key_id = %s; want kid-wo", keyID)
	}
}

func TestKeySetCreateRejectsBothSecrets(t *testing.T) {
	f := newFakeGraph(t)
	r := &trustFrameworkKeySetResource{client: f.client()}
	sr, ot := keySetResourceSchema(t)
	str := func(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }
	plan := keySetRaw(ot, map[string]tftypes.Value{
		"id": str(testKeySetID), "use": str("enc"), "key_type": str("oct"), "secret": str("a"),
		"key_id": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	})
	cfg := keySetRaw(ot, map[string]tftypes.Value{
		"id": str(testKeySetID), "use": str("enc"), "key_type": str("oct"), "secret": str("a"), "secret_wo": str("b"),
	})
	req := resource.CreateRequest{
		Config: tfsdk.Config{Schema: sr.Schema, Raw: cfg},
		Plan:   tfsdk.Plan{Schema: sr.Schema, Raw: plan},
	}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(ot, nil)}}
	r.Create(context.Background(), req, &resp)
	if !resp.Diagnostics.HasError() || resp.Diagnostics.Errors()[0].Summary() != "Conflicting secrets" {
		t.Errorf("diagnostics = %v; want Conflicting secrets", resp.Diagnostics)
	}
	if n := len(f.calls()); n != 0 {
		t.Errorf("calls = %d; nothing may be sent to Graph", n)
	}
}

func TestKeySetValidateConfig(t *testing.T) {
	r := &trustFrameworkKeySetResource{}
	sr, ot := keySetResourceSchema(t)
	str := func(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }
	base := func(extra map[string]tftypes.Value) tftypes.Value {
		vals := map[string]tftypes.Value{"id": str(testKeySetID), "use": str("enc"), "key_type": str("oct")}
		for k, v := range extra {
			vals[k] = v
		}
		return keySetRaw(ot, vals)
	}
	cases := []struct {
		name    string
		raw     tftypes.Value
		wantErr string // "" for valid
	}{
		{"generate", base(nil), ""},
		{"secret", base(map[string]tftypes.Value{"secret": str("a")}), ""},
		{"write-only secret with version", base(map[string]tftypes.Value{"secret_wo": str("a"), "secret_wo_version": tftypes.NewValue(tftypes.Number, 1)}), ""},
		{"secret and write-only secret", base(map[string]tftypes.Value{"secret": str("a"), "secret_wo": str("b")}), "Conflicting secrets"},
		{"version without write-only secret", base(map[string]tftypes.Value{"secret_wo_version": tftypes.NewValue(tftypes.Number, 1)}), "Missing secret_wo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := resource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: sr.Schema, Raw: tc.raw}}, &resp)
			if tc.wantErr == "" {
				if resp.Diagnostics.HasError() {
					t.Errorf("diagnostics = %v; want none", resp.Diagnostics)
				}
				return
			}
			if len(resp.Diagnostics.Errors()) != 1 || resp.Diagnostics.Errors()[0].Summary() != tc.wantErr {
				t.Errorf("diagnostics = %v; want one %q", resp.Diagnostics, tc.wantErr)
			}
		})
	}
}

func TestNormalizeKeyValues(t *testing.T) {
	for in, want := range map[string]string{"RSA": "RSA", "rsa": "RSA", "Oct": "oct", "OCT": "oct"} {
		if got, ok := normalizeKeyType(in); !ok || got != want {
			t.Errorf("normalizeKeyType(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := normalizeKeyType("EC"); ok {
		t.Error("EC is not supported")
	}
	for in, want := range map[string]string{"sig": "sig", "SIG": "sig", "Enc": "enc"} {
		if got, ok := normalizeKeyUse(in); !ok || got != want {
			t.Errorf("normalizeKeyUse(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := normalizeKeyUse("both"); ok {
		t.Error("both is not a key use")
	}
}

func TestKeySetMissingOnReadAndDelete(t *testing.T) {
	const gone = `{"error":{"code":"AADB2C90073","message":"KeyContainer with 'id': 'B2C_1A_Gone' cannot be found in the directory 'contoso.onmicrosoft.com'."}}`
	f := newFakeGraph(t).
		on(http.MethodGet, "/trustFramework/keySets/B2C_1A_Gone", http.StatusBadRequest, gone).
		on(http.MethodDelete, "/trustFramework/keySets/B2C_1A_Gone", http.StatusNotFound, gone)
	c := f.client()
	if _, err := readKeySet(context.Background(), c, "B2C_1A_Gone"); !isKeySetNotFound(err) {
		t.Errorf("read: err = %v; want a not-found", err)
	}
	if err := deleteKeySet(context.Background(), c, "B2C_1A_Gone"); err != nil {
		t.Errorf("delete of a missing key set: %v; want nil", err)
	}
}
