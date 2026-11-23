package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &trustFrameworkPolicyDataSource{}
	_ datasource.DataSourceWithConfigure = &trustFrameworkPolicyDataSource{}
)

type trustFrameworkPolicyDataSource struct{ client *graphClient }

// NewTrustFrameworkPolicyDataSource reads one custom policy.
func NewTrustFrameworkPolicyDataSource() datasource.DataSource {
	return &trustFrameworkPolicyDataSource{}
}

type trustFrameworkPolicyDataModel struct {
	ID           types.String `tfsdk:"id"`
	Policy       types.String `tfsdk:"policy"`
	BasePolicyID types.String `tfsdk:"base_policy_id"`
	TenantID     types.String `tfsdk:"tenant_id"`
}

func (d *trustFrameworkPolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trust_framework_policy"
}

func (d *trustFrameworkPolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads one Azure AD B2C custom policy.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Required: true, Description: "Policy id, e.g. B2C_1A_TrustFrameworkBase."},
			"policy":         schema.StringAttribute{Computed: true, Description: "The policy XML as stored in B2C."},
			"base_policy_id": schema.StringAttribute{Computed: true, Description: "The <BasePolicy><PolicyId> of the policy, or null when it has no base policy."},
			"tenant_id":      schema.StringAttribute{Computed: true, Description: "The TenantId attribute of the root element, or null when it is not set."},
		},
	}
}

func (d *trustFrameworkPolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	c, msg := clientFromProviderData(req.ProviderData)
	if msg != "" {
		resp.Diagnostics.AddError("Unexpected provider data", msg)
		return
	}
	d.client = c
}

func (d *trustFrameworkPolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m trustFrameworkPolicyDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc, err := getPolicy(ctx, d.client, m.ID.ValueString())
	if err != nil {
		if isGraphNotFound(err) {
			resp.Diagnostics.AddError("Policy not found", fmt.Sprintf("No custom policy %q exists in the tenant.", m.ID.ValueString()))
			return
		}
		resp.Diagnostics.AddError("Policy read failed", err.Error())
		return
	}
	doc = strings.TrimPrefix(doc, utf8BOM)
	m.Policy = types.StringValue(doc)
	m.BasePolicyID, m.TenantID = types.StringNull(), types.StringNull()
	if info, err := parsePolicyInfo(doc); err == nil {
		pm := policyModelFromInfo(info)
		m.BasePolicyID, m.TenantID = pm.BasePolicyID, pm.TenantID
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
