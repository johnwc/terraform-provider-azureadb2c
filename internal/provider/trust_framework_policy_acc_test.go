package provider

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccTenantDomainEnv names the B2C tenant domain the policy tests upload to,
// e.g. contoso.onmicrosoft.com.
const testAccTenantDomainEnv = "AZUREADB2C_ACC_TENANT_DOMAIN"

// testAccPolicyTemplate is a minimal policy. {{TENANT}}, {{POLICY_ID}},
// {{CLAIM_ID}}, {{DISPLAY_NAME}}, {{BASE_POLICY}} and {{CLAIMS_PROVIDERS}} are
// replaced by testAccPolicy.
const testAccPolicyTemplate = `<?xml version="1.0" encoding="utf-8"?>
<TrustFrameworkPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06" PolicySchemaVersion="0.3.0.0"
  TenantId="{{TENANT}}" PolicyId="{{POLICY_ID}}" PublicPolicyUri="http://{{TENANT}}/{{POLICY_ID}}">{{BASE_POLICY}}
  <BuildingBlocks>
    <ClaimsSchema>
      <ClaimType Id="{{CLAIM_ID}}">
        <DisplayName>{{DISPLAY_NAME}}</DisplayName>
        <DataType>string</DataType>
      </ClaimType>
    </ClaimsSchema>
  </BuildingBlocks>{{CLAIMS_PROVIDERS}}
</TrustFrameworkPolicy>`

// testAccPolicyBaseRefTemplate is the <BasePolicy> element of an extension policy.
const testAccPolicyBaseRefTemplate = `
  <BasePolicy>
    <TenantId>{{TENANT}}</TenantId>
    <PolicyId>{{BASE_POLICY_ID}}</PolicyId>
  </BasePolicy>`

// testAccPolicyKeyRefTemplate is a claims provider whose token issuer uses the
// key container {{KEY_SET_ID}}.
const testAccPolicyKeyRefTemplate = `
  <ClaimsProviders>` + testAccPolicyEngineProvider + `    <ClaimsProvider>
      <DisplayName>Token Issuer</DisplayName>
      <TechnicalProfiles>
        <TechnicalProfile Id="TfAccJwtIssuer">
          <DisplayName>JWT Issuer</DisplayName>
          <Protocol Name="None" />
          <OutputTokenFormat>JWT</OutputTokenFormat>
          <CryptographicKeys>
            <Key Id="issuer_secret" StorageReferenceId="{{KEY_SET_ID}}" />
          </CryptographicKeys>
        </TechnicalProfile>
      </TechnicalProfiles>
    </ClaimsProvider>
  </ClaimsProviders>`

// testAccPolicyEngineProvider is the policy engine claims provider B2C requires
// in every policy that has no base policy.
const testAccPolicyEngineProvider = `
    <ClaimsProvider>
      <DisplayName>Trustframework Policy Engine TechnicalProfiles</DisplayName>
      <TechnicalProfiles>
        <TechnicalProfile Id="TpEngine_c3bd4fe2-1775-4013-b91d-35f16d377d13">
          <DisplayName>Trustframework Policy Engine Default Technical Profile</DisplayName>
          <Protocol Name="None" />
          <Metadata>
            <Item Key="url">{service:te}</Item>
          </Metadata>
        </TechnicalProfile>
      </TechnicalProfiles>
    </ClaimsProvider>`

// testAccPolicyEngineTemplate is a claims providers element holding only the
// policy engine provider.
const testAccPolicyEngineTemplate = `
  <ClaimsProviders>` + testAccPolicyEngineProvider + `
  </ClaimsProviders>`

// testAccPolicy renders a policy from the template. basePolicyXML and
// claimsProvidersXML may be empty.
func testAccPolicy(tenant, policyID, claimID, displayName, basePolicyXML, claimsProvidersXML string) string {
	return strings.NewReplacer("{{TENANT}}", tenant, "{{POLICY_ID}}", policyID, "{{CLAIM_ID}}", claimID, "{{DISPLAY_NAME}}", displayName,
		"{{BASE_POLICY}}", basePolicyXML, "{{CLAIMS_PROVIDERS}}", claimsProvidersXML).
		Replace(testAccPolicyTemplate)
}

// testAccMinimalPolicy renders the minimal base policy.
func testAccMinimalPolicy(tenant, policyID, displayName string) string {
	return testAccPolicy(tenant, policyID, "tfAccTestClaim", displayName, "", testAccPolicyEngineTemplate)
}

// testAccKeyedBasePolicy renders a base policy that references the key container keySetID.
func testAccKeyedBasePolicy(tenant, policyID, keySetID string) string {
	return testAccPolicy(tenant, policyID, "tfAccTestClaim", "Terraform test base claim", "",
		strings.NewReplacer("{{KEY_SET_ID}}", keySetID).Replace(testAccPolicyKeyRefTemplate))
}

// testAccExtensionPolicy renders an extension policy whose BasePolicy is basePolicyID.
func testAccExtensionPolicy(tenant, policyID, basePolicyID string) string {
	return testAccPolicy(tenant, policyID, "tfAccTestExtensionClaim", "Terraform test extension claim",
		strings.NewReplacer("{{TENANT}}", tenant, "{{BASE_POLICY_ID}}", basePolicyID).Replace(testAccPolicyBaseRefTemplate), "")
}

// testAccTenantDomain returns the tenant domain, skipping the test when it is unset.
func testAccTenantDomain(t *testing.T) string {
	t.Helper()
	d := os.Getenv(testAccTenantDomainEnv)
	if d == "" {
		t.Skip("set " + testAccTenantDomainEnv + " (e.g. contoso.onmicrosoft.com) to run the policy acceptance tests")
	}
	return d
}

// TestAccTrustFrameworkPolicy_base uploads a minimal base policy, updates it in
// place, reads it with the data source, imports it by id and destroys it. Run
// with TF_ACC=1, ARM_* credentials and AZUREADB2C_ACC_TENANT_DOMAIN pointing at
// a disposable dev B2C tenant.
func TestAccTrustFrameworkPolicy_base(t *testing.T) {
	tenant := testAccTenantDomain(t)
	id := testAccName()
	const rn = "azureadb2c_trust_framework_policy.test"
	const dn = "data.azureadb2c_trust_framework_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDestroy,
		Steps: []resource.TestStep{
			{ // create
				Config: testAccPolicyConfig(testAccMinimalPolicy(tenant, id, "Terraform test claim")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "id", id),
					resource.TestCheckResourceAttr(rn, "tenant_id", tenant),
					resource.TestCheckNoResourceAttr(rn, "base_policy_id"),
				),
			},
			{ // in-place update, then read with the data source
				Config: testAccPolicyConfig(testAccMinimalPolicy(tenant, id, "Terraform test claim (updated)")) + testAccPolicyDataSourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "id", id),
					resource.TestCheckResourceAttr(dn, "id", id),
					resource.TestCheckResourceAttr(dn, "tenant_id", tenant),
					resource.TestCheckResourceAttrSet(dn, "policy"),
				),
			},
			{ // import by id; the server XML formatting may differ from config
				ResourceName:            rn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"policy"},
			},
		},
	})
}

// TestAccTrustFrameworkPolicy_ordering creates a key set, a base policy that
// references it and an extension policy whose BasePolicy is the base policy in
// one apply. Terraform must create them in that order and destroy them in
// reverse, or Graph rejects the upload or the delete. Run with TF_ACC=1,
// ARM_* credentials and AZUREADB2C_ACC_TENANT_DOMAIN pointing at a disposable
// dev B2C tenant.
func TestAccTrustFrameworkPolicy_ordering(t *testing.T) {
	tenant := testAccTenantDomain(t)
	keySetID, baseID, extID := testAccName(), testAccName(), testAccName()
	const ks = "azureadb2c_trust_framework_key_set.test"
	const base = "azureadb2c_trust_framework_policy.base"
	const ext = "azureadb2c_trust_framework_policy.extension"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOrderingConfig(tenant, keySetID, baseID, extID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ks, "id", keySetID),
					resource.TestCheckResourceAttr(base, "id", baseID),
					resource.TestCheckNoResourceAttr(base, "base_policy_id"),
					resource.TestCheckResourceAttr(ext, "id", extID),
					resource.TestCheckResourceAttr(ext, "base_policy_id", baseID),
					resource.TestCheckResourceAttrPair(ext, "base_policy_id", base, "id"),
				),
			},
		},
	})
}

// testAccOrderingConfig wires the policies to each other through Terraform
// references: the base policy XML names the key set id and the extension XML
// names the base policy id.
func testAccOrderingConfig(tenant, keySetID, baseID, extID string) string {
	return fmt.Sprintf(`
resource "azureadb2c_trust_framework_key_set" "test" {
  id       = %[1]q
  use      = "sig"
  key_type = "RSA"
}

resource "azureadb2c_trust_framework_policy" "base" {
  policy = <<XML
%[2]s
XML
}

resource "azureadb2c_trust_framework_policy" "extension" {
  policy = <<XML
%[3]s
XML
}
`, keySetID,
		testAccKeyedBasePolicy(tenant, baseID, "${azureadb2c_trust_framework_key_set.test.id}"),
		testAccExtensionPolicy(tenant, extID, "${azureadb2c_trust_framework_policy.base.id}"))
}

func testAccPolicyConfig(policy string) string {
	return fmt.Sprintf(`
resource "azureadb2c_trust_framework_policy" "test" {
  policy = <<XML
%s
XML
}
`, policy)
}

const testAccPolicyDataSourceConfig = `
data "azureadb2c_trust_framework_policy" "test" {
  id = azureadb2c_trust_framework_policy.test.id
}
`
