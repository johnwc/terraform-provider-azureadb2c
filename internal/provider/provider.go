package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/terraprovider/go-msadmin/authx"
	"github.com/terraprovider/go-msadmin/retry"
	"github.com/terraprovider/tf-msadmin/authschema"
)

var _ provider.Provider = &azureADB2CProvider{}

// azureADB2CProvider implements the Azure AD B2C custom policy provider.
type azureADB2CProvider struct{ version string }

// New returns the provider constructor for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &azureADB2CProvider{version: version} }
}

func (p *azureADB2CProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azureadb2c"
	resp.Version = p.version
}

// providerModel is the shared azuread/azurerm-aligned auth block.
type providerModel struct {
	authschema.Model
}

func (p *azureADB2CProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Azure AD B2C custom policies (Identity Experience Framework) and policy keys through the Microsoft Graph trustFramework API. " +
			"Authentication mirrors the AzureAD/AzureRM providers (ARM_*/AZURE_* env vars supported). " +
			"A client_secret or client certificate set in this block is used instead of a sign-in method enabled only through environment variables, unless the block also sets use_cli, use_msi or an OIDC option. " +
			"App-only needs the Microsoft Graph application permissions Policy.ReadWrite.TrustFramework and TrustFrameworkKeySet.ReadWrite.All.",
		Attributes: authschema.Attributes(),
	}
}

func (p *azureADB2CProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Explicit config overlaid onto the ARM_*/AZURE_* environment.
	tp, err := authConfig(m.Model).Build()
	if err != nil {
		resp.Diagnostics.AddError("Authentication configuration error", err.Error())
		return
	}

	// Acquire a Graph token now so bad credentials fail before any resource call.
	if _, err := tp.Token(ctx, graphResource); err != nil {
		resp.Diagnostics.AddError("Authentication failed", err.Error())
		return
	}

	c := &graphClient{
		Tokens:  tp,
		HTTP:    &http.Client{Transport: retry.NewTransport(newSecretRedactingDebugTransport(nil), retry.Config{})},
		BaseURL: graphBaseURL,
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *azureADB2CProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTrustFrameworkPolicyResource,
		NewTrustFrameworkKeySetResource,
	}
}

func (p *azureADB2CProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTrustFrameworkPolicyDataSource,
		NewTrustFrameworkKeySetDataSource,
	}
}

// clientFromProviderData returns the configured client, or an error message
// when the provider data has an unexpected type. nil data (before the provider
// is configured) returns nil and no error.
func clientFromProviderData(data any) (*graphClient, string) {
	if data == nil {
		return nil, ""
	}
	c, ok := data.(*graphClient)
	if !ok {
		return nil, "Expected *provider.graphClient as provider data. Please report this to the provider developers."
	}
	return c, ""
}

// authConfig resolves the authentication settings. A client secret or client
// certificate set in the provider block is used instead of a sign-in method
// enabled only through ARM_*/AZURE_* environment variables, unless the block
// itself sets use_cli, use_msi or an OIDC option. Without an explicit
// credential the merged settings are returned unchanged.
func authConfig(m authschema.Model) authx.Config {
	cfg := m.Config()
	explicitSecret := m.ClientSecret.ValueString() != ""
	explicitCertificate := m.ClientCertificate.ValueString() != "" || m.ClientCertificatePath.ValueString() != ""
	if !explicitSecret && !explicitCertificate {
		return cfg
	}
	if !explicitSecret {
		cfg.ClientSecret = ""
	}
	if !m.UseCLI.ValueBool() {
		cfg.UseCLI = false
	}
	if !m.UseMSI.ValueBool() {
		cfg.UseMSI = false
	}
	explicitOIDC := m.UseOIDC.ValueBool() || m.OIDCToken.ValueString() != "" || m.OIDCTokenFilePath.ValueString() != "" ||
		m.OIDCRequestToken.ValueString() != "" || m.OIDCRequestURL.ValueString() != "" || m.ADOServiceConnectionID.ValueString() != ""
	if !explicitOIDC {
		cfg.UseOIDC = false
		cfg.OIDCToken, cfg.OIDCTokenFilePath, cfg.OIDCRequestToken, cfg.OIDCRequestURL, cfg.ADOServiceConnectionID = "", "", "", "", ""
	}
	return cfg
}
