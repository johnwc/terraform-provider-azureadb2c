package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ basetypes.StringTypable                    = XMLType{}
	_ basetypes.StringValuableWithSemanticEquals = XMLValue{}
)

// XMLType is a string type holding an XML document. Two documents that differ
// only in the XML declaration, comments, whitespace between elements or
// attribute order are semantically equal (see canonicalXML).
type XMLType struct {
	basetypes.StringType
}

// String returns a human readable name of the type.
func (t XMLType) String() string { return "provider.XMLType" }

// ValueType returns the value type of XMLType.
func (t XMLType) ValueType(_ context.Context) attr.Value { return XMLValue{} }

// Equal reports whether o is an XMLType.
func (t XMLType) Equal(o attr.Type) bool {
	other, ok := o.(XMLType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

// ValueFromString wraps a StringValue in an XMLValue.
func (t XMLType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return XMLValue{StringValue: in}, nil
}

// ValueFromTerraform converts a Terraform value into an XMLValue.
func (t XMLType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	sv, ok := v.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", v)
	}
	xv, diags := t.ValueFromString(ctx, sv)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to XMLValue: %v", diags)
	}
	return xv, nil
}

// XMLValue is the value of an XMLType attribute.
type XMLValue struct {
	basetypes.StringValue
}

// NewXMLValue returns a known XMLValue.
func NewXMLValue(s string) XMLValue { return XMLValue{StringValue: basetypes.NewStringValue(s)} }

// Type returns XMLType.
func (v XMLValue) Type(_ context.Context) attr.Type { return XMLType{} }

// Equal reports whether o is an XMLValue with the same state and exact string.
func (v XMLValue) Equal(o attr.Value) bool {
	other, ok := o.(XMLValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals reports whether the two documents have the same canonical
// form. A document that cannot be parsed is only equal to an identical string.
func (v XMLValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(XMLValue)
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("An unexpected value type was received while comparing XML documents: %T. Please report this to the provider developers.", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	return xmlSemanticallyEqual(v.ValueString(), other.ValueString()), diags
}
