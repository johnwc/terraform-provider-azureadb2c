package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/terraprovider/go-msadmin/httpx"
	"github.com/terraprovider/go-msadmin/retry"
	"github.com/terraprovider/tf-msadmin/authschema"
)

// testAccProtoV6ProviderFactories serves the azureadb2c provider to acceptance tests.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"azureadb2c": providerserver.NewProtocol6WithError(New("acc")()),
}

// testAccPreCheck skips acceptance tests unless the tenant + a credential are
// configured. Acceptance tests create and destroy real objects and must run
// against a disposable dev B2C tenant (never one with real data).
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("ARM_TENANT_ID") == "" || os.Getenv("ARM_CLIENT_ID") == "" {
		t.Skip("set ARM_TENANT_ID, ARM_CLIENT_ID and a credential to run acceptance tests")
	}
	hasCred := os.Getenv("ARM_CLIENT_SECRET") != "" ||
		os.Getenv("ARM_CLIENT_CERTIFICATE") != "" ||
		os.Getenv("ARM_CLIENT_CERTIFICATE_PATH") != "" ||
		os.Getenv("ARM_USE_OIDC") != "" ||
		os.Getenv("ARM_OIDC_TOKEN") != "" ||
		os.Getenv("ARM_USE_CLI") != ""
	if !hasCred {
		t.Skip("no credential set (ARM_CLIENT_SECRET / ARM_CLIENT_CERTIFICATE[_PATH] / ARM_USE_OIDC / ARM_USE_CLI)")
	}
}

// testAccGraphClient builds a Graph client from the same ARM_*/AZURE_*
// environment the provider uses.
func testAccGraphClient() (*graphClient, error) {
	tp, err := authschema.Model{}.Config().Build()
	if err != nil {
		return nil, err
	}
	return &graphClient{
		Tokens:  tp,
		HTTP:    &http.Client{Transport: retry.NewTransport(httpx.NewDebugTransport(nil), retry.Config{})},
		BaseURL: graphBaseURL,
	}, nil
}

// testAccCheckDestroy fails when a key set or policy of the final state still
// exists in the tenant. A 404 from Graph means it is destroyed.
func testAccCheckDestroy(s *terraform.State) error {
	c, err := testAccGraphClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for name, rs := range s.RootModule().Resources {
		var getErr error
		switch rs.Type {
		case "azureadb2c_trust_framework_key_set":
			_, getErr = readKeySet(ctx, c, rs.Primary.ID)
		case "azureadb2c_trust_framework_policy":
			_, getErr = getPolicy(ctx, c, rs.Primary.ID)
		default:
			continue
		}
		switch {
		case getErr == nil:
			return fmt.Errorf("%s (%s) still exists after destroy", name, rs.Primary.ID)
		case !isKeySetNotFound(getErr):
			return fmt.Errorf("checking %s (%s): %w", name, rs.Primary.ID, getErr)
		}
	}
	return nil
}

// TestProviderSchema serves the provider and fetches its schema, which runs the
// framework's validation of every provider, resource and data source schema.
func TestProviderSchema(t *testing.T) {
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("provider server: %v", err)
	}
	resp, err := srv.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema: %v", err)
	}
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Errorf("schema error: %s: %s", d.Summary, d.Detail)
		}
	}
	if resp.Provider == nil {
		t.Fatal("no provider schema")
	}
	for _, attr := range []string{"tenant_id", "client_id", "client_secret", "use_oidc", "use_cli", "use_msi", "environment"} {
		if !schemaHasAttribute(resp.Provider, attr) {
			t.Errorf("provider schema is missing %s", attr)
		}
	}
	for _, name := range []string{"azureadb2c_trust_framework_policy", "azureadb2c_trust_framework_key_set"} {
		if resp.ResourceSchemas[name] == nil {
			t.Errorf("missing resource %s", name)
		}
		if resp.DataSourceSchemas[name] == nil {
			t.Errorf("missing data source %s", name)
		}
	}
	if len(resp.ResourceSchemas) != 2 || len(resp.DataSourceSchemas) != 2 {
		t.Errorf("resources = %d, data sources = %d; want 2 and 2", len(resp.ResourceSchemas), len(resp.DataSourceSchemas))
	}

	ks := resp.ResourceSchemas["azureadb2c_trust_framework_key_set"]
	if ks != nil {
		wo := schemaAttribute(ks, "secret_wo")
		if wo == nil || !wo.WriteOnly || !wo.Sensitive {
			t.Errorf("secret_wo = %+v; want write-only and sensitive", wo)
		}
		if s := schemaAttribute(ks, "secret"); s == nil || !s.Sensitive || s.WriteOnly {
			t.Errorf("secret = %+v; want sensitive, not write-only", s)
		}
	}
}

func schemaAttribute(s *tfprotov6.Schema, name string) *tfprotov6.SchemaAttribute {
	if s == nil || s.Block == nil {
		return nil
	}
	for _, a := range s.Block.Attributes {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func schemaHasAttribute(s *tfprotov6.Schema, name string) bool {
	return schemaAttribute(s, name) != nil
}

func TestAuthConfig(t *testing.T) {
	const zero = "00000000-0000-0000-0000-000000000000"
	explicit := func(mod func(*authschema.Model)) authschema.Model {
		m := authschema.Model{TenantID: types.StringValue(zero), ClientID: types.StringValue(zero)}
		mod(&m)
		return m
	}
	secret := func(m *authschema.Model) { m.ClientSecret = types.StringValue("explicit") }
	cases := []struct {
		name  string
		env   map[string]string
		model authschema.Model
		want  string
	}{
		{"explicit secret over env oidc, cli and msi",
			map[string]string{"ARM_USE_OIDC": "true", "ARM_OIDC_TOKEN": "ambient-token", "ARM_USE_CLI": "true", "ARM_USE_MSI": "true"},
			explicit(secret), "secret"},
		{"explicit secret over GitHub Actions oidc env",
			map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ambient-token"},
			explicit(secret), "secret"},
		{"explicit certificate over env oidc and env secret",
			map[string]string{"ARM_USE_OIDC": "true", "ARM_OIDC_TOKEN": "ambient-token", "ARM_CLIENT_SECRET": "ambient-secret"},
			explicit(func(m *authschema.Model) { m.ClientCertificatePath = types.StringValue("cert.pfx") }), "certificate"},
		{"explicit use_cli kept", nil,
			explicit(func(m *authschema.Model) { secret(m); m.UseCLI = types.BoolValue(true) }), "cli"},
		{"explicit use_msi kept", nil,
			explicit(func(m *authschema.Model) { secret(m); m.UseMSI = types.BoolValue(true) }), "msi"},
		{"explicit oidc kept", nil,
			explicit(func(m *authschema.Model) {
				secret(m)
				m.UseOIDC, m.OIDCToken = types.BoolValue(true), types.StringValue("explicit-token")
			}), "oidc"},
		{"env secret with env oidc is unchanged",
			map[string]string{"ARM_USE_OIDC": "true", "ARM_OIDC_TOKEN": "ambient-token", "ARM_CLIENT_SECRET": "ambient-secret"},
			explicit(func(*authschema.Model) {}), "oidc"},
		{"nothing explicit keeps env oidc",
			map[string]string{"ARM_USE_OIDC": "true", "ARM_OIDC_TOKEN": "ambient-token"},
			authschema.Model{}, "oidc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"ARM_USE_OIDC", "ARM_OIDC_TOKEN", "ARM_USE_CLI", "ARM_USE_MSI", "ARM_CLIENT_SECRET", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg := authConfig(tc.model)
			if got := cfg.Method(); got != tc.want {
				t.Errorf("method = %q; want %q", got, tc.want)
			}
			if !tc.model.TenantID.IsNull() && (cfg.TenantID != zero || cfg.ClientID != zero) {
				t.Errorf("tenant %q / client %q; want both kept", cfg.TenantID, cfg.ClientID)
			}
		})
	}
}
