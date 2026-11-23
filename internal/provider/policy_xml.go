package provider

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// policyRootElement is the local name of a custom policy's root element.
const policyRootElement = "TrustFrameworkPolicy"

// b2cCustomPrefix is the prefix of every custom policy and policy key container id.
const b2cCustomPrefix = "B2C_1A_"

// policyInfo holds the identifying values of a custom policy document.
type policyInfo struct {
	RootName     string // local name of the root element
	PolicyID     string // root PolicyId attribute ("" when missing)
	TenantID     string // root TenantId attribute ("" when missing)
	BasePolicyID string // <BasePolicy><PolicyId> text ("" when missing)
}

// parsePolicyInfo reads the root element name, the PolicyId and TenantId root
// attributes and the <BasePolicy><PolicyId> text of a policy document. It reads
// the whole document, so a malformed document is an error. Only the first
// <BasePolicy><PolicyId> is used.
func parsePolicyInfo(doc string) (policyInfo, error) {
	var info policyInfo
	dec := newXMLDecoder(doc)
	var stack []string
	var base strings.Builder
	inBase, baseSeen := false, false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return policyInfo{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				if info.RootName != "" {
					return policyInfo{}, errors.New("more than one root element")
				}
				info.RootName = t.Name.Local
				for _, a := range t.Attr {
					if a.Name.Space != "" {
						continue
					}
					switch a.Name.Local {
					case "PolicyId":
						info.PolicyID = strings.TrimSpace(a.Value)
					case "TenantId":
						info.TenantID = strings.TrimSpace(a.Value)
					}
				}
			}
			stack = append(stack, t.Name.Local)
			inBase = !baseSeen && len(stack) == 3 && stack[1] == "BasePolicy" && stack[2] == "PolicyId"
			if inBase {
				baseSeen = true
				base.Reset()
			}
		case xml.EndElement:
			if inBase {
				info.BasePolicyID = strings.TrimSpace(base.String())
				inBase = false
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if inBase {
				base.Write(t)
			}
		}
	}
	if info.RootName == "" {
		return policyInfo{}, errors.New("no root element")
	}
	return info, nil
}

// validatePolicyXML checks a policy document and returns one message per
// problem: well-formed XML, a TrustFrameworkPolicy root element, a PolicyId
// starting with B2C_1A_, and no unresolved {Settings:...} token.
func validatePolicyXML(doc string) []string {
	if _, err := canonicalXML(doc); err != nil {
		return []string{fmt.Sprintf("The policy is not well-formed XML: %s.", err)}
	}
	info, err := parsePolicyInfo(doc)
	if err != nil {
		return []string{fmt.Sprintf("The policy is not well-formed XML: %s.", err)}
	}
	var problems []string
	if info.RootName != policyRootElement {
		problems = append(problems, fmt.Sprintf("The root element is <%s>; a custom policy must have a <%s> root element.", info.RootName, policyRootElement))
	}
	switch {
	case info.PolicyID == "":
		problems = append(problems, "The root element has no PolicyId attribute.")
	case !hasB2CPrefix(info.PolicyID):
		problems = append(problems, fmt.Sprintf("PolicyId %q must start with %s.", info.PolicyID, b2cCustomPrefix))
	}
	if tok := findSettingsToken(doc); tok != "" {
		problems = append(problems, fmt.Sprintf("The policy still contains the unresolved token %s. Replace every {Settings:...} placeholder before uploading, e.g. with templatefile().", tok))
	}
	return problems
}

// hasB2CPrefix reports whether id starts with B2C_1A_, ignoring case.
func hasB2CPrefix(id string) bool {
	return len(id) >= len(b2cCustomPrefix) && strings.EqualFold(id[:len(b2cCustomPrefix)], b2cCustomPrefix)
}

// settingsTokenRE matches a {Settings:...} placeholder, e.g. {Settings:TenantName}.
var settingsTokenRE = regexp.MustCompile(`(?i)\{settings:[^{}<>"\s]*\}?`)

// findSettingsToken returns the first unresolved {Settings:...} token in the
// attribute values and text of doc, or "". Comments are ignored. Claim
// resolvers such as {Policy:TenantObjectId} or {OIDC:LoginHint} are not tokens.
// If doc is not well-formed the raw text is searched.
func findSettingsToken(doc string) string {
	dec := newXMLDecoder(doc)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return ""
		}
		if err != nil {
			return settingsTokenRE.FindString(doc)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			for _, a := range t.Attr {
				if m := settingsTokenRE.FindString(a.Value); m != "" {
					return m
				}
			}
		case xml.CharData:
			if m := settingsTokenRE.FindString(string(t)); m != "" {
				return m
			}
		}
	}
}
