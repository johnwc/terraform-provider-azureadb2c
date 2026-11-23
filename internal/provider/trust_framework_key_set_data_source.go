package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &trustFrameworkKeySetDataSource{}
	_ datasource.DataSourceWithConfigure = &trustFrameworkKeySetDataSource{}
)

type trustFrameworkKeySetDataSource struct{ client *graphClient }

// NewTrustFrameworkKeySetDataSource reads one policy key container.
func NewTrustFrameworkKeySetDataSource() datasource.DataSource {
	return &trustFrameworkKeySetDataSource{}
}

type trustFrameworkKeySetDataModel struct {
	ID      types.String `tfsdk:"id"`
	Use     types.String `tfsdk:"use"`
	KeyType types.String `tfsdk:"key_type"`
	KeyID   types.String `tfsdk:"key_id"`
}

func (d *trustFrameworkKeySetDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trust_framework_key_set"
}

func (d *trustFrameworkKeySetDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads one Azure AD B2C policy key container (key set). Key material is never read.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Required: true, Description: "Container name including the B2C_1A_ prefix."},
			"use":      schema.StringAttribute{Computed: true, Description: "Usage of the active key: sig or enc. Null when the container has no key."},
			"key_type": schema.StringAttribute{Computed: true, Description: "Type of the active key: RSA or oct. Null when the container has no key."},
			"key_id":   schema.StringAttribute{Computed: true, Description: "Key id (kid) of the active key. Null when the container has no key."},
		},
	}
}

func (d *trustFrameworkKeySetDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	c, msg := clientFromProviderData(req.ProviderData)
	if msg != "" {
		resp.Diagnostics.AddError("Unexpected provider data", msg)
		return
	}
	d.client = c
}

func (d *trustFrameworkKeySetDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m trustFrameworkKeySetDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ks, err := readKeySet(ctx, d.client, m.ID.ValueString())
	if err != nil {
		if isKeySetNotFound(err) {
			resp.Diagnostics.AddError("Key set not found", fmt.Sprintf("No key set %q exists in the tenant.", m.ID.ValueString()))
			return
		}
		resp.Diagnostics.AddError("Key set read failed", err.Error())
		return
	}
	m.Use, m.KeyType, m.KeyID = keySetDataFromServer(ks, time.Now())
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// keySetDataFromServer returns use, key_type and key_id of the active key (see
// selectKey), or nulls.
func keySetDataFromServer(ks trustFrameworkKeySet, now time.Time) (use, keyType, keyID types.String) {
	use, keyType, keyID = types.StringNull(), types.StringNull(), types.StringNull()
	k := selectKey(ks, "", now)
	if k == nil {
		return use, keyType, keyID
	}
	if k.Use != "" {
		u, ok := normalizeKeyUse(k.Use)
		if !ok {
			u = k.Use
		}
		use = types.StringValue(u)
	}
	if k.Kty != "" {
		kt, ok := normalizeKeyType(k.Kty)
		if !ok {
			kt = k.Kty
		}
		keyType = types.StringValue(kt)
	}
	if k.Kid != "" {
		keyID = types.StringValue(k.Kid)
	}
	return use, keyType, keyID
}
