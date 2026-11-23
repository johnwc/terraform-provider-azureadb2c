package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &trustFrameworkPolicyResource{}
	_ resource.ResourceWithConfigure      = &trustFrameworkPolicyResource{}
	_ resource.ResourceWithImportState    = &trustFrameworkPolicyResource{}
	_ resource.ResourceWithValidateConfig = &trustFrameworkPolicyResource{}
	_ resource.ResourceWithModifyPlan     = &trustFrameworkPolicyResource{}
)

// trustFrameworkPoliciesPath is the Graph collection of custom policies.
const trustFrameworkPoliciesPath = "/trustFramework/policies"

type trustFrameworkPolicyResource struct{ client *graphClient }

// NewTrustFrameworkPolicyResource manages one custom policy (one <TrustFrameworkPolicy> document).
func NewTrustFrameworkPolicyResource() resource.Resource { return &trustFrameworkPolicyResource{} }

type trustFrameworkPolicyModel struct {
	ID           types.String `tfsdk:"id"`
	Policy       XMLValue     `tfsdk:"policy"`
	BasePolicyID types.String `tfsdk:"base_policy_id"`
	TenantID     types.String `tfsdk:"tenant_id"`
}

func (r *trustFrameworkPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trust_framework_policy"
}

func (r *trustFrameworkPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Uploads one Azure AD B2C custom policy (a <TrustFrameworkPolicy> XML document). " +
			"The policy id comes from the PolicyId attribute of the root element; changing it replaces the policy. " +
			"Pass a parent policy's id into the child's XML (e.g. with templatefile()) so Terraform uploads the base policy first.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Policy id, read from the PolicyId attribute of the root element.",
			},
			"policy": schema.StringAttribute{
				Required:   true,
				CustomType: XMLType{},
				Description: "The full policy XML. Differences only in the XML declaration, comments, whitespace between elements " +
					"and attribute order are not changes. Every {Settings:...} placeholder must be resolved.",
			},
			"base_policy_id": schema.StringAttribute{
				Computed:    true,
				Description: "The <BasePolicy><PolicyId> of the policy, or null when it has no base policy.",
			},
			"tenant_id": schema.StringAttribute{
				Computed:    true,
				Description: "The TenantId attribute of the root element, or null when it is not set.",
			},
		},
	}
}

func (r *trustFrameworkPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c, msg := clientFromProviderData(req.ProviderData)
	if msg != "" {
		resp.Diagnostics.AddError("Unexpected provider data", msg)
		return
	}
	r.client = c
}

func (r *trustFrameworkPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var policy XMLValue
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("policy"), &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validatePolicyValue(policy)...)
}

// validatePolicyValue validates a known policy value; null and unknown values pass.
func validatePolicyValue(policy XMLValue) diag.Diagnostics {
	var diags diag.Diagnostics
	if policy.IsNull() || policy.IsUnknown() {
		return diags
	}
	for _, p := range validatePolicyXML(policy.ValueString()) {
		diags.AddAttributeError(path.Root("policy"), "Invalid policy XML", p)
	}
	return diags
}

// ModifyPlan sets id, base_policy_id and tenant_id from the planned XML and
// replaces the policy when its PolicyId changes.
func (r *trustFrameworkPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan trustFrameworkPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state trustFrameworkPolicyModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.ID
	}
	planned, replace := policyPlan(plan.Policy, prior)
	plan.ID, plan.BasePolicyID, plan.TenantID = planned.ID, planned.BasePolicyID, planned.TenantID
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	if replace {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("id"))
	}
}

// policyPlan returns the planned computed values for a planned policy value and
// whether the policy id differs from the prior id. An unknown policy plans
// unknown values; a policy that cannot be parsed (already reported by
// ValidateConfig) also plans unknown values.
func policyPlan(policy XMLValue, priorID types.String) (trustFrameworkPolicyModel, bool) {
	unknown := trustFrameworkPolicyModel{ID: types.StringUnknown(), BasePolicyID: types.StringUnknown(), TenantID: types.StringUnknown()}
	if policy.IsNull() || policy.IsUnknown() {
		return unknown, false
	}
	info, err := parsePolicyInfo(policy.ValueString())
	if err != nil || info.PolicyID == "" {
		return unknown, false
	}
	m := policyModelFromInfo(info)
	replace := !priorID.IsNull() && !priorID.IsUnknown() && priorID.ValueString() != info.PolicyID
	return m, replace
}

// policyModelFromInfo maps the parsed identifying values onto a model (Policy unset).
func policyModelFromInfo(info policyInfo) trustFrameworkPolicyModel {
	m := trustFrameworkPolicyModel{ID: types.StringValue(info.PolicyID), BasePolicyID: types.StringNull(), TenantID: types.StringNull()}
	if info.BasePolicyID != "" {
		m.BasePolicyID = types.StringValue(info.BasePolicyID)
	}
	if info.TenantID != "" {
		m.TenantID = types.StringValue(info.TenantID)
	}
	return m
}

func (r *trustFrameworkPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan trustFrameworkPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc := plan.Policy.ValueString()
	info, ok := policyInfoForApply(doc, &resp.Diagnostics)
	if !ok {
		return
	}
	err := defaultDependencyRetry.do(ctx, func() error { return createPolicy(ctx, r.client, doc) })
	if err != nil {
		if isGraphConflict(err) {
			resp.Diagnostics.AddError("Policy already exists",
				fmt.Sprintf("The policy %s already exists in the tenant. Import it to manage it with Terraform:\n\n  terraform import azureadb2c_trust_framework_policy.<name> %s\n\n%s", info.PolicyID, info.PolicyID, err))
			return
		}
		resp.Diagnostics.AddError("Policy upload failed", err.Error())
		return
	}
	m := policyModelFromInfo(info)
	m.Policy = plan.Policy
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *trustFrameworkPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state trustFrameworkPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc, err := getPolicy(ctx, r.client, state.ID.ValueString())
	if err != nil {
		if isGraphNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Policy read failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, policyStateFromServer(state, doc))...)
}

// policyStateFromServer merges the server XML into the prior state. The server
// XML is stored only when it is not semantically equal to the prior value, so
// the formatting from config is kept. id keeps the prior value when it differs
// only in case.
func policyStateFromServer(state trustFrameworkPolicyModel, doc string) *trustFrameworkPolicyModel {
	doc = strings.TrimPrefix(doc, utf8BOM)
	if state.Policy.IsNull() || state.Policy.IsUnknown() || !xmlSemanticallyEqual(state.Policy.ValueString(), doc) {
		state.Policy = NewXMLValue(doc)
	}
	info, err := parsePolicyInfo(doc)
	if err != nil {
		if state.BasePolicyID.IsUnknown() {
			state.BasePolicyID = types.StringNull()
		}
		if state.TenantID.IsUnknown() {
			state.TenantID = types.StringNull()
		}
		return &state
	}
	m := policyModelFromInfo(info)
	if info.PolicyID != "" && !strings.EqualFold(info.PolicyID, state.ID.ValueString()) {
		state.ID = m.ID
	}
	state.BasePolicyID, state.TenantID = m.BasePolicyID, m.TenantID
	return &state
}

func (r *trustFrameworkPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state trustFrameworkPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc := plan.Policy.ValueString()
	info, ok := policyInfoForApply(doc, &resp.Diagnostics)
	if !ok {
		return
	}
	id := state.ID.ValueString()
	if !strings.EqualFold(info.PolicyID, id) {
		created, err := replacePolicy(ctx, r.client, defaultDependencyRetry, id, doc)
		if !created {
			resp.Diagnostics.AddError("Policy upload failed", err.Error())
			return
		}
		m := policyModelFromInfo(info)
		m.Policy = plan.Policy
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		if err != nil {
			resp.Diagnostics.AddError("Previous policy not deleted",
				fmt.Sprintf("The policy was uploaded as %q, but the previous policy %q could not be deleted: %s. Delete it by hand once nothing references it.", info.PolicyID, id, err))
		}
		return
	}
	err := defaultDependencyRetry.do(ctx, func() error { return updatePolicy(ctx, r.client, id, doc) })
	if err != nil {
		resp.Diagnostics.AddError("Policy upload failed", err.Error())
		return
	}
	m := policyModelFromInfo(info)
	m.ID = state.ID
	m.Policy = plan.Policy
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// replacePolicy uploads doc as a new policy and then deletes the policy oldID.
// It is used when the PolicyId in the XML was not known at plan time and turns
// out to differ from the managed policy. created reports whether the new policy
// exists; a non-nil error with created true is the failed delete of oldID.
func replacePolicy(ctx context.Context, c *graphClient, retry dependencyRetry, oldID, doc string) (created bool, err error) {
	if err := retry.do(ctx, func() error { return createPolicy(ctx, c, doc) }); err != nil {
		return false, err
	}
	return true, deletePolicy(ctx, c, oldID)
}

func (r *trustFrameworkPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state trustFrameworkPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := deletePolicy(ctx, r.client, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Policy delete failed", err.Error())
	}
}

func (r *trustFrameworkPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// policyInfoForApply parses and validates the policy XML at apply time, when a
// value that was unknown at plan time is first known.
func policyInfoForApply(doc string, diags *diag.Diagnostics) (policyInfo, bool) {
	if problems := validatePolicyXML(doc); len(problems) > 0 {
		for _, p := range problems {
			diags.AddAttributeError(path.Root("policy"), "Invalid policy XML", p)
		}
		return policyInfo{}, false
	}
	info, err := parsePolicyInfo(doc)
	if err != nil {
		diags.AddAttributeError(path.Root("policy"), "Invalid policy XML", err.Error())
		return policyInfo{}, false
	}
	return info, true
}

// policyPath returns the Graph path of one policy.
func policyPath(id string) string { return trustFrameworkPoliciesPath + "/" + url.PathEscape(id) }

// createPolicy uploads a new policy.
func createPolicy(ctx context.Context, c *graphClient, doc string) error {
	_, err := graphDoXML(ctx, c, http.MethodPost, trustFrameworkPoliciesPath, []byte(doc))
	return err
}

// getPolicy downloads the XML of one policy.
func getPolicy(ctx context.Context, c *graphClient, id string) (string, error) {
	raw, err := graphDoXML(ctx, c, http.MethodGet, policyPath(id)+"/$value", nil)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// updatePolicy replaces the XML of an existing policy.
func updatePolicy(ctx context.Context, c *graphClient, id, doc string) error {
	_, err := graphDoXML(ctx, c, http.MethodPut, policyPath(id)+"/$value", []byte(doc))
	return err
}

// deletePolicy deletes a policy. A missing policy is treated as deleted.
func deletePolicy(ctx context.Context, c *graphClient, id string) error {
	_, err := graphDoXML(ctx, c, http.MethodDelete, policyPath(id), nil)
	if err != nil && !isGraphNotFound(err) {
		return err
	}
	return nil
}
