package provider

import (
	"strings"
	"testing"
)

const testExtensionPolicy = `<?xml version="1.0" encoding="utf-8"?>
<TrustFrameworkPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06"
  PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_TrustFrameworkExtensions"
  PublicPolicyUri="http://contoso.onmicrosoft.com/B2C_1A_TrustFrameworkExtensions">
  <BasePolicy>
    <TenantId>contoso.onmicrosoft.com</TenantId>
    <PolicyId>
      B2C_1A_TrustFrameworkBase
    </PolicyId>
  </BasePolicy>
  <BuildingBlocks>
    <ClaimsSchema>
      <ClaimType Id="hint">
        <DisplayName>{OIDC:LoginHint}</DisplayName>
        <DataType>string</DataType>
        <DefaultPartnerClaimTypes>
          <Protocol Name="OpenIdConnect" PartnerClaimType="{service:te}" />
        </DefaultPartnerClaimTypes>
        <AdminHelpText>{Policy:TenantObjectId}</AdminHelpText>
      </ClaimType>
    </ClaimsSchema>
  </BuildingBlocks>
</TrustFrameworkPolicy>`

func TestParsePolicyInfo(t *testing.T) {
	info, err := parsePolicyInfo(testExtensionPolicy)
	if err != nil {
		t.Fatalf("parsePolicyInfo: %v", err)
	}
	want := policyInfo{
		RootName:     "TrustFrameworkPolicy",
		PolicyID:     "B2C_1A_TrustFrameworkExtensions",
		TenantID:     "contoso.onmicrosoft.com",
		BasePolicyID: "B2C_1A_TrustFrameworkBase",
	}
	if info != want {
		t.Errorf("info = %+v\nwant %+v", info, want)
	}
}

func TestParsePolicyInfoNoBaseNoTenant(t *testing.T) {
	info, err := parsePolicyInfo(`<TrustFrameworkPolicy xmlns="urn:x" PolicyId="B2C_1A_base"><BuildingBlocks><PolicyId>not-base</PolicyId></BuildingBlocks></TrustFrameworkPolicy>`)
	if err != nil {
		t.Fatalf("parsePolicyInfo: %v", err)
	}
	if info.PolicyID != "B2C_1A_base" || info.TenantID != "" || info.BasePolicyID != "" {
		t.Errorf("info = %+v", info)
	}
}

func TestParsePolicyInfoIgnoresNestedBasePolicy(t *testing.T) {
	doc := `<TrustFrameworkPolicy PolicyId="B2C_1A_x"><X><BasePolicy><PolicyId>B2C_1A_nested</PolicyId></BasePolicy></X></TrustFrameworkPolicy>`
	info, err := parsePolicyInfo(doc)
	if err != nil || info.BasePolicyID != "" {
		t.Errorf("info = %+v, err = %v; want no base policy", info, err)
	}
}

func TestParsePolicyInfoFirstBasePolicyOnly(t *testing.T) {
	doc := `<TrustFrameworkPolicy PolicyId="B2C_1A_x"><BasePolicy><PolicyId>B2C_1A_first</PolicyId></BasePolicy><BasePolicy><PolicyId>B2C_1A_second</PolicyId></BasePolicy></TrustFrameworkPolicy>`
	info, err := parsePolicyInfo(doc)
	if err != nil || info.BasePolicyID != "B2C_1A_first" {
		t.Errorf("info = %+v, err = %v; want the first base policy", info, err)
	}
}

func TestParsePolicyInfoIgnoresQualifiedAttributes(t *testing.T) {
	doc := `<TrustFrameworkPolicy xmlns:o="urn:o" o:PolicyId="B2C_1A_other" PolicyId="B2C_1A_x"/>`
	info, err := parsePolicyInfo(doc)
	if err != nil || info.PolicyID != "B2C_1A_x" {
		t.Errorf("info = %+v, err = %v", info, err)
	}
}

func TestParsePolicyInfoMalformed(t *testing.T) {
	for _, doc := range []string{"", "<TrustFrameworkPolicy PolicyId=\"B2C_1A_x\">", "<a/><b/>", "plain text"} {
		if _, err := parsePolicyInfo(doc); err == nil {
			t.Errorf("parsePolicyInfo(%q): want an error", doc)
		}
	}
}

func TestValidatePolicyXML(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string // substring of the only problem; "" for none
	}{
		{"valid", testExtensionPolicy, ""},
		{"lowercase prefix", `<TrustFrameworkPolicy PolicyId="b2c_1a_x"/>`, ""},
		{"malformed", `<TrustFrameworkPolicy PolicyId="B2C_1A_x">`, "not well-formed"},
		{"wrong root", `<Policy PolicyId="B2C_1A_x"/>`, "root element is <Policy>"},
		{"no policy id", `<TrustFrameworkPolicy TenantId="contoso.onmicrosoft.com"/>`, "no PolicyId"},
		{"no prefix", `<TrustFrameworkPolicy PolicyId="SignUpSignIn"/>`, "must start with B2C_1A_"},
		{"B2C_1_ prefix", `<TrustFrameworkPolicy PolicyId="B2C_1_SignUp"/>`, "must start with B2C_1A_"},
		{"settings token in text", strings.Replace(testExtensionPolicy, "<TenantId>contoso.onmicrosoft.com</TenantId>", "<TenantId>{Settings:Tenant}</TenantId>", 1), "{Settings:Tenant}"},
		{"settings token in attribute", strings.Replace(testExtensionPolicy, `TenantId="contoso.onmicrosoft.com"`, `TenantId="{Settings:TenantName}.onmicrosoft.com"`, 1), "{Settings:TenantName}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validatePolicyXML(tc.doc)
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("problems = %q; want none", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Errorf("problems = %q; want one containing %q", got, tc.want)
			}
		})
	}
}

func TestValidatePolicyXMLReportsAllProblems(t *testing.T) {
	got := validatePolicyXML(`<Policy PolicyId="x">{Settings:A}</Policy>`)
	if len(got) != 3 {
		t.Errorf("problems = %q; want root, prefix and settings token", got)
	}
}

func TestFindSettingsToken(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"none", testExtensionPolicy, ""},
		{"claim resolvers", `<a b="{Policy:TenantObjectId}">{OIDC:LoginHint} {service:te} {Culture:LCID}</a>`, ""},
		{"text", `<a><b>{Settings:IdentityExperienceFrameworkAppId}</b></a>`, "{Settings:IdentityExperienceFrameworkAppId}"},
		{"attribute", `<a b="https://login.microsoftonline.com/{Settings:Tenant}/v2.0"/>`, "{Settings:Tenant}"},
		{"first of two", `<a><b>{Settings:First}</b><c>{Settings:Second}</c></a>`, "{Settings:First}"},
		{"case-insensitive", `<a>{settings:lower}</a>`, "{settings:lower}"},
		{"in comment only", `<a><!-- {Settings:Old} --></a>`, ""},
		{"unclosed", `<a>{Settings:Broken</a>`, "{Settings:Broken"},
		{"malformed falls back to raw text", `<a>{Settings:X}`, "{Settings:X}"},
		{"settings without colon", `<a>{Settings}</a>`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findSettingsToken(tc.doc); got != tc.want {
				t.Errorf("findSettingsToken = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestHasB2CPrefix(t *testing.T) {
	for id, want := range map[string]bool{
		"B2C_1A_x": true, "b2c_1a_x": true, "B2c_1A_": true,
		"B2C_1_x": false, "x_B2C_1A_": false, "": false, "B2C": false,
	} {
		if got := hasB2CPrefix(id); got != want {
			t.Errorf("hasB2CPrefix(%q) = %v; want %v", id, got, want)
		}
	}
}
