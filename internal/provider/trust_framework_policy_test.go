package provider

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

const testBasePolicy = `<?xml version="1.0" encoding="utf-8"?>
<TrustFrameworkPolicy xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06" PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_base">
  <BuildingBlocks />
</TrustFrameworkPolicy>`

func TestPolicyCRUDRequests(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/policies", http.StatusCreated, `{"id":"B2C_1A_base"}`).
		on(http.MethodGet, "/trustFramework/policies/B2C_1A_base/$value", http.StatusOK, testBasePolicy).
		on(http.MethodPut, "/trustFramework/policies/B2C_1A_base/$value", http.StatusOK, "").
		on(http.MethodDelete, "/trustFramework/policies/B2C_1A_base", http.StatusNoContent, "")
	c := f.client()
	ctx := context.Background()

	if err := createPolicy(ctx, c, testBasePolicy); err != nil {
		t.Fatalf("createPolicy: %v", err)
	}
	doc, err := getPolicy(ctx, c, "B2C_1A_base")
	if err != nil || doc != testBasePolicy {
		t.Fatalf("getPolicy = %q, %v", doc, err)
	}
	if err := updatePolicy(ctx, c, "B2C_1A_base", testBasePolicy); err != nil {
		t.Fatalf("updatePolicy: %v", err)
	}
	if err := deletePolicy(ctx, c, "B2C_1A_base"); err != nil {
		t.Fatalf("deletePolicy: %v", err)
	}
	want := []string{
		"POST /trustFramework/policies",
		"GET /trustFramework/policies/B2C_1A_base/$value",
		"PUT /trustFramework/policies/B2C_1A_base/$value",
		"DELETE /trustFramework/policies/B2C_1A_base",
	}
	if got := f.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q\nwant %q", got, want)
	}
	for _, i := range []int{0, 2} {
		if r := f.request(i); r.ContentType != "application/xml" || r.Body != testBasePolicy {
			t.Errorf("request %d: Content-Type %q, body %q", i, r.ContentType, r.Body)
		}
	}
}

func TestDeletePolicyNotFound(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodDelete, "/trustFramework/policies/B2C_1A_gone", http.StatusNotFound, `{"error":{"code":"x","message":"not found"}}`)
	if err := deletePolicy(context.Background(), f.client(), "B2C_1A_gone"); err != nil {
		t.Errorf("deletePolicy of a missing policy: %v", err)
	}
	f2 := newFakeGraph(t).on(http.MethodDelete, "/trustFramework/policies/B2C_1A_x", http.StatusForbidden, `{"error":{"code":"x","message":"denied"}}`)
	if err := deletePolicy(context.Background(), f2.client(), "B2C_1A_x"); err == nil {
		t.Error("deletePolicy: want the 403 error")
	}
}

func TestGetPolicyNotFound(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodGet, "/trustFramework/policies/B2C_1A_gone/$value", http.StatusNotFound, `{"error":{"code":"x","message":"not found"}}`)
	_, err := getPolicy(context.Background(), f.client(), "B2C_1A_gone")
	if !isGraphNotFound(err) {
		t.Errorf("err = %v; want not found", err)
	}
}

func TestCreatePolicyRetriesWhileBaseMissing(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/policies", http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Validation failed: 1 validation error(s) found in policy \"B2C_1A_EXT\" of tenant \"contoso.onmicrosoft.com\".Policy with 'policyId': B2C_1A_BASE cannot be found in the directory '00000000-0000-0000-0000-000000000000'."}}`).
		on(http.MethodPost, "/trustFramework/policies", http.StatusCreated, `{"id":"B2C_1A_ext"}`)
	c := f.client()
	err := testFastRetry.do(context.Background(), func() error { return createPolicy(context.Background(), c, testBasePolicy) })
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := len(f.calls()); n != 2 {
		t.Errorf("calls = %d; want 2", n)
	}
}

func TestCreatePolicyDoesNotRetryOtherErrors(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/policies", http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Schema validation error."}}`)
	c := f.client()
	err := testFastRetry.do(context.Background(), func() error { return createPolicy(context.Background(), c, testBasePolicy) })
	if err == nil {
		t.Fatal("create: want an error")
	}
	if n := len(f.calls()); n != 1 {
		t.Errorf("calls = %d; want 1", n)
	}
}

func TestCreatePolicyConflict(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/policies", http.StatusConflict, `{"error":{"code":"Conflict","message":"Policy already exists."}}`)
	err := createPolicy(context.Background(), f.client(), testBasePolicy)
	if !isGraphConflict(err) {
		t.Errorf("err = %v; want a conflict", err)
	}
	if isDependencyNotReady(err) {
		t.Error("a conflict must not be retried")
	}
}

func TestPolicyPlan(t *testing.T) {
	ext := testExtensionPolicy
	cases := []struct {
		name        string
		policy      XMLValue
		prior       types.String
		wantID      types.String
		wantBase    types.String
		wantTenant  types.String
		wantReplace bool
	}{
		{"create", NewXMLValue(ext), types.StringNull(),
			types.StringValue("B2C_1A_TrustFrameworkExtensions"), types.StringValue("B2C_1A_TrustFrameworkBase"), types.StringValue("contoso.onmicrosoft.com"), false},
		{"same id", NewXMLValue(ext), types.StringValue("B2C_1A_TrustFrameworkExtensions"),
			types.StringValue("B2C_1A_TrustFrameworkExtensions"), types.StringValue("B2C_1A_TrustFrameworkBase"), types.StringValue("contoso.onmicrosoft.com"), false},
		{"changed id", NewXMLValue(ext), types.StringValue("B2C_1A_Old"),
			types.StringValue("B2C_1A_TrustFrameworkExtensions"), types.StringValue("B2C_1A_TrustFrameworkBase"), types.StringValue("contoso.onmicrosoft.com"), true},
		{"no base, no tenant", NewXMLValue(`<TrustFrameworkPolicy PolicyId="B2C_1A_x"/>`), types.StringNull(),
			types.StringValue("B2C_1A_x"), types.StringNull(), types.StringNull(), false},
		{"unknown policy", NewXMLUnknown(), types.StringValue("B2C_1A_x"),
			types.StringUnknown(), types.StringUnknown(), types.StringUnknown(), false},
		{"malformed policy", NewXMLValue("<TrustFrameworkPolicy"), types.StringValue("B2C_1A_x"),
			types.StringUnknown(), types.StringUnknown(), types.StringUnknown(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, replace := policyPlan(tc.policy, tc.prior)
			if !m.ID.Equal(tc.wantID) || !m.BasePolicyID.Equal(tc.wantBase) || !m.TenantID.Equal(tc.wantTenant) || replace != tc.wantReplace {
				t.Errorf("policyPlan = id %s, base %s, tenant %s, replace %v; want %s, %s, %s, %v",
					m.ID, m.BasePolicyID, m.TenantID, replace, tc.wantID, tc.wantBase, tc.wantTenant, tc.wantReplace)
			}
		})
	}
}

func TestPolicyStateFromServer(t *testing.T) {
	configured := testBasePolicy
	reformatted := strings.Replace(strings.Replace(configured, "\n  ", "", -1),
		`PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_base"`,
		`PolicyId="B2C_1A_base" PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com"`, 1)
	changed := strings.Replace(configured, "<BuildingBlocks />", "<BuildingBlocks><ClaimsSchema /></BuildingBlocks>", 1)

	state := trustFrameworkPolicyModel{ID: types.StringValue("B2C_1A_base"), Policy: NewXMLValue(configured), BasePolicyID: types.StringNull(), TenantID: types.StringNull()}

	got := policyStateFromServer(state, reformatted)
	if got.Policy.ValueString() != configured {
		t.Errorf("semantically equal server XML replaced the configured XML:\n%s", got.Policy.ValueString())
	}
	if !got.TenantID.Equal(types.StringValue("contoso.onmicrosoft.com")) || !got.BasePolicyID.IsNull() || !got.ID.Equal(types.StringValue("B2C_1A_base")) {
		t.Errorf("state = %+v", got)
	}

	got = policyStateFromServer(state, changed)
	if got.Policy.ValueString() != changed {
		t.Errorf("changed server XML not stored: %s", got.Policy.ValueString())
	}

	got = policyStateFromServer(state, utf8BOM+reformatted)
	if got.Policy.ValueString() != configured {
		t.Error("a byte order mark from the server must not cause a diff")
	}

	// Import: no prior policy.
	imported := trustFrameworkPolicyModel{ID: types.StringValue("b2c_1a_BASE"), Policy: NewXMLNull(), BasePolicyID: types.StringNull(), TenantID: types.StringNull()}
	got = policyStateFromServer(imported, reformatted)
	if got.Policy.ValueString() != reformatted || got.ID.ValueString() != "b2c_1a_BASE" {
		t.Errorf("imported state = %+v; want the server XML and the import id kept", got)
	}
}

func TestValidatePolicyValue(t *testing.T) {
	if d := validatePolicyValue(NewXMLUnknown()); d.HasError() {
		t.Errorf("unknown: %v", d)
	}
	if d := validatePolicyValue(NewXMLNull()); d.HasError() {
		t.Errorf("null: %v", d)
	}
	if d := validatePolicyValue(NewXMLValue(testBasePolicy)); d.HasError() {
		t.Errorf("valid: %v", d)
	}
	d := validatePolicyValue(NewXMLValue(`<TrustFrameworkPolicy PolicyId="x">{Settings:Y}</TrustFrameworkPolicy>`))
	if len(d.Errors()) != 2 {
		t.Errorf("diagnostics = %v; want 2 errors", d)
	}
}

func TestReplacePolicyCreatesThenDeletesOld(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/policies", http.StatusCreated, `{"id":"B2C_1A_new"}`).
		on(http.MethodDelete, "/trustFramework/policies/B2C_1A_old", http.StatusNoContent, ``)
	created, err := replacePolicy(context.Background(), f.client(), testFastRetry, "B2C_1A_old", testBasePolicy)
	if !created || err != nil {
		t.Fatalf("created = %v, err = %v; want true, nil", created, err)
	}
	calls := f.calls()
	if len(calls) != 2 || !strings.HasPrefix(calls[0], http.MethodPost) || !strings.HasPrefix(calls[1], http.MethodDelete) {
		t.Errorf("calls = %v; want POST then DELETE", calls)
	}
}

func TestReplacePolicyKeepsOldWhenCreateFails(t *testing.T) {
	f := newFakeGraph(t).on(http.MethodPost, "/trustFramework/policies", http.StatusBadRequest, `{"error":{"code":"AADB2C","message":"Schema validation error."}}`)
	created, err := replacePolicy(context.Background(), f.client(), testFastRetry, "B2C_1A_old", testBasePolicy)
	if created || err == nil {
		t.Fatalf("created = %v, err = %v; want false and an error", created, err)
	}
	if n := len(f.calls()); n != 1 {
		t.Errorf("calls = %d; want 1 (no delete)", n)
	}
}

func TestReplacePolicyReportsFailedDeleteOfOld(t *testing.T) {
	f := newFakeGraph(t).
		on(http.MethodPost, "/trustFramework/policies", http.StatusCreated, `{"id":"B2C_1A_new"}`).
		on(http.MethodDelete, "/trustFramework/policies/B2C_1A_old", http.StatusConflict, `{"error":{"code":"AADB2C","message":"The policy is referenced by another policy."}}`)
	created, err := replacePolicy(context.Background(), f.client(), testFastRetry, "B2C_1A_old", testBasePolicy)
	if !created || err == nil {
		t.Fatalf("created = %v, err = %v; want true and the delete error", created, err)
	}
}
