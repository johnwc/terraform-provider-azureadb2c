package provider

import (
	"strings"
	"testing"
)

const canonBase = `<?xml version="1.0" encoding="utf-8"?>
<TrustFrameworkPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06" PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_TrustFrameworkBase">
  <!-- building blocks -->
  <BuildingBlocks>
    <ClaimsSchema>
      <ClaimType Id="email">
        <DisplayName>Email Address</DisplayName>
        <DataType>string</DataType>
      </ClaimType>
    </ClaimsSchema>
  </BuildingBlocks>
</TrustFrameworkPolicy>
`

const canonDecl = `<?xml version="1.0" encoding="utf-8"?>`

const canonCompact = `<TrustFrameworkPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06" PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_TrustFrameworkBase">` +
	`<BuildingBlocks><ClaimsSchema><ClaimType Id="email"><DisplayName>Email Address</DisplayName><DataType>string</DataType></ClaimType></ClaimsSchema></BuildingBlocks></TrustFrameworkPolicy>`

type xmlCase struct {
	name string
	doc  string
}

func TestCanonicalXMLEqualVariants(t *testing.T) {
	variants := []xmlCase{
		{"identical", canonBase},
		{"no declaration", strings.Replace(canonBase, canonDecl+"\n", "", 1)},
		{"other declaration", strings.Replace(canonBase, canonDecl, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`, 1)},
		{"no comments", strings.Replace(canonBase, "<!-- building blocks -->", "", 1)},
		{"extra comments", strings.Replace(canonBase, "<DataType>", "<!-- type --><DataType>", 1)},
		{"no whitespace", canonCompact},
		{"tabs and CRLF", strings.ReplaceAll(strings.ReplaceAll(canonBase, "  ", "\t"), "\n", "\r\n")},
		{"attribute order", strings.Replace(canonBase,
			`PolicySchemaVersion="0.3.0.0" TenantId="contoso.onmicrosoft.com" PolicyId="B2C_1A_TrustFrameworkBase"`,
			`PolicyId="B2C_1A_TrustFrameworkBase" TenantId="contoso.onmicrosoft.com" PolicySchemaVersion="0.3.0.0"`, 1)},
		{"namespace declaration order", strings.Replace(canonBase,
			`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06"`,
			`xmlns="http://schemas.microsoft.com/online/cpim/schemas/2013/06" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`, 1)},
		{"single quotes", strings.Replace(canonBase, `Id="email"`, `Id='email'`, 1)},
		{"byte order mark", utf8BOM + canonBase},
	}
	want, err := canonicalXML(canonBase)
	if err != nil {
		t.Fatalf("canonicalXML(base): %v", err)
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalXML(tc.doc)
			if err != nil {
				t.Fatalf("canonicalXML: %v", err)
			}
			if got != want {
				t.Errorf("canonical form differs:\n got %s\nwant %s", got, want)
			}
			if !xmlSemanticallyEqual(canonBase, tc.doc) {
				t.Error("xmlSemanticallyEqual = false")
			}
		})
	}
}

func TestCanonicalXMLSelfClosing(t *testing.T) {
	if !xmlSemanticallyEqual(`<a><b x="1"/></a>`, `<a><b x="1"></b></a>`) {
		t.Error("<b/> and <b></b> should be equal")
	}
}

func TestCanonicalXMLNotEqual(t *testing.T) {
	cases := []xmlCase{
		{"changed text", strings.Replace(canonBase, "Email Address", "E-mail Address", 1)},
		{"changed attribute value", strings.Replace(canonBase, `Id="email"`, `Id="mail"`, 1)},
		{"added attribute", strings.Replace(canonBase, `<ClaimType Id="email">`, `<ClaimType Id="email" Extra="1">`, 1)},
		{"removed element", strings.Replace(canonBase, "<DataType>string</DataType>", "", 1)},
		{"renamed element", strings.Replace(strings.Replace(canonBase, "<DataType>", "<Type>", 1), "</DataType>", "</Type>", 1)},
		{"text whitespace", strings.Replace(canonBase, "<DataType>string</DataType>", "<DataType> string </DataType>", 1)},
		{"changed namespace", strings.Replace(canonBase, "2013/06", "2013/07", 1)},
		{"element order", strings.Replace(canonBase,
			"<DisplayName>Email Address</DisplayName>\n        <DataType>string</DataType>",
			"<DataType>string</DataType>\n        <DisplayName>Email Address</DisplayName>", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.doc == canonBase {
				t.Fatal("test case did not change the document")
			}
			if xmlSemanticallyEqual(canonBase, tc.doc) {
				t.Error("xmlSemanticallyEqual = true; want false")
			}
		})
	}
}

func TestCanonicalXMLLeafWhitespace(t *testing.T) {
	withSpace := `<Metadata><Item Key="Delimiter"> </Item></Metadata>`
	empty := `<Metadata><Item Key="Delimiter"></Item></Metadata>`
	if xmlSemanticallyEqual(withSpace, empty) {
		t.Error("a whitespace-only leaf must differ from an empty one")
	}
	got, err := canonicalXML(withSpace)
	if err != nil {
		t.Fatalf("canonicalXML: %v", err)
	}
	if !strings.Contains(got, `<Item Key="Delimiter"> </Item>`) {
		t.Errorf("leaf whitespace dropped: %s", got)
	}
}

func TestCanonicalXMLSiblingWhitespaceIgnored(t *testing.T) {
	a := "<a>\n  <b>1</b>\n  <c/>\n</a>"
	b := "<a><b>1</b><c/></a>"
	if !xmlSemanticallyEqual(a, b) {
		t.Error("whitespace between sibling elements should be ignored")
	}
}

func TestCanonicalXMLSpacePreserve(t *testing.T) {
	a := `<a xml:space="preserve"> <b>1</b> </a>`
	b := `<a xml:space="preserve"><b>1</b></a>`
	if xmlSemanticallyEqual(a, b) {
		t.Error("xml:space=preserve must keep whitespace between elements")
	}
	inherited := `<a xml:space="preserve"><b> <c/> </b></a>`
	compact := `<a xml:space="preserve"><b><c/></b></a>`
	if xmlSemanticallyEqual(inherited, compact) {
		t.Error("xml:space=preserve must be inherited by descendants")
	}
	overridden := `<a xml:space="preserve"><b xml:space="default"> <c/> </b></a>`
	overriddenCompact := `<a xml:space="preserve"><b xml:space="default"><c/></b></a>`
	if !xmlSemanticallyEqual(overridden, overriddenCompact) {
		t.Error("xml:space=default must end preservation")
	}
}

func TestCanonicalXMLPrefixesResolved(t *testing.T) {
	a := `<p:a xmlns:p="urn:x"><p:b>1</p:b></p:a>`
	b := `<q:a xmlns:q="urn:x"><q:b>1</q:b></q:a>`
	ca, errA := canonicalXML(a)
	cb, errB := canonicalXML(b)
	if errA != nil || errB != nil {
		t.Fatalf("errors: %v, %v", errA, errB)
	}
	// The element names resolve to the same namespace; only the xmlns
	// declarations (kept as attributes) differ.
	if !strings.Contains(ca, "<{urn:x}b>1</{urn:x}b>") || !strings.Contains(cb, "<{urn:x}b>1</{urn:x}b>") {
		t.Errorf("canonical forms: %s / %s", ca, cb)
	}
}

func TestCanonicalXMLEscaping(t *testing.T) {
	a := `<a v="x &amp; y">1 &lt; 2</a>`
	b := `<a v='x &#38; y'><![CDATA[1 < 2]]></a>`
	if !xmlSemanticallyEqual(a, b) {
		ca, _ := canonicalXML(a)
		cb, _ := canonicalXML(b)
		t.Errorf("escaped forms differ: %s / %s", ca, cb)
	}
}

func TestCanonicalXMLKeepsProcessingInstructions(t *testing.T) {
	if xmlSemanticallyEqual(`<a><?pi data?></a>`, `<a></a>`) {
		t.Error("a non-declaration processing instruction is significant")
	}
}

func TestCanonicalXMLMalformed(t *testing.T) {
	cases := []xmlCase{
		{"empty", ""},
		{"only whitespace", "  \n "},
		{"only declaration", `<?xml version="1.0"?>`},
		{"unclosed", "<a><b></b>"},
		{"mismatched", "<a><b></a></b>"},
		{"two roots", "<a/><b/>"},
		{"text outside", "<a/>trailing"},
		{"bad attribute", `<a x=1/>`},
		{"not xml", "hello"},
		{"unknown entity", "<a>&nope;</a>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := canonicalXML(tc.doc); err == nil {
				t.Error("canonicalXML: want an error")
			}
		})
	}
	// Malformed documents are only equal to an identical string.
	if !xmlSemanticallyEqual("<a>", "<a>") {
		t.Error("identical malformed strings should be equal")
	}
	if xmlSemanticallyEqual("<a>", "<a/>") || xmlSemanticallyEqual("<a/>", "<a>") {
		t.Error("a malformed document must not equal a well-formed one")
	}
}

func TestCanonicalXMLIgnoresServerTenantObjectID(t *testing.T) {
	uploaded := `<TrustFrameworkPolicy PolicyId="B2C_1A_x" TenantId="contoso.onmicrosoft.com"><a TenantObjectId="1"/></TrustFrameworkPolicy>`
	stored := `<TrustFrameworkPolicy PolicyId="B2C_1A_x" TenantId="contoso.onmicrosoft.com" TenantObjectId="00000000-0000-0000-0000-000000000000"><a TenantObjectId="1"/></TrustFrameworkPolicy>`
	if !xmlSemanticallyEqual(uploaded, stored) {
		t.Error("the root TenantObjectId the server adds must not count as a change")
	}
	nested := `<TrustFrameworkPolicy PolicyId="B2C_1A_x" TenantId="contoso.onmicrosoft.com"><a TenantObjectId="2"/></TrustFrameworkPolicy>`
	if xmlSemanticallyEqual(uploaded, nested) {
		t.Error("TenantObjectId below the root is ordinary content")
	}
}
