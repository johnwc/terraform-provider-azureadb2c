package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestXMLValueSemanticEquals(t *testing.T) {
	ctx := context.Background()
	a := NewXMLValue(`<?xml version="1.0"?><a x="1" y="2"><!-- c --><b>t</b></a>`)
	cases := []struct {
		name string
		v    XMLValue
		want bool
	}{
		{"reformatted", NewXMLValue("<a y=\"2\" x=\"1\">\n  <b>t</b>\n</a>\n"), true},
		{"changed text", NewXMLValue(`<a x="1" y="2"><b>u</b></a>`), false},
		{"changed attribute", NewXMLValue(`<a x="1" y="3"><b>t</b></a>`), false},
		{"malformed", NewXMLValue(`<a x="1" y="2"><b>t</b>`), false},
		{"null", NewXMLNull(), false},
		{"unknown", NewXMLUnknown(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, diags := a.StringSemanticEquals(ctx, tc.v)
			if diags.HasError() {
				t.Fatalf("diagnostics: %v", diags)
			}
			if got != tc.want {
				t.Errorf("StringSemanticEquals = %v; want %v", got, tc.want)
			}
		})
	}
	if _, diags := a.StringSemanticEquals(ctx, types.StringValue("<a/>")); !diags.HasError() {
		t.Error("comparing with a plain StringValue should report an error")
	}
}

func TestXMLValueEqual(t *testing.T) {
	a := NewXMLValue("<a/>")
	if !a.Equal(NewXMLValue("<a/>")) {
		t.Error("identical values should be Equal")
	}
	if a.Equal(NewXMLValue("<a></a>")) {
		t.Error("Equal must compare exact strings")
	}
	if a.Equal(types.StringValue("<a/>")) {
		t.Error("an XMLValue is not Equal to a StringValue")
	}
	if !NewXMLNull().Equal(NewXMLNull()) || NewXMLNull().Equal(NewXMLUnknown()) {
		t.Error("null/unknown equality is wrong")
	}
}

func TestXMLTypeRoundTrip(t *testing.T) {
	ctx := context.Background()
	typ := XMLType{}
	for _, in := range []tftypes.Value{
		tftypes.NewValue(tftypes.String, "<a/>"),
		tftypes.NewValue(tftypes.String, nil),
		tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	} {
		v, err := typ.ValueFromTerraform(ctx, in)
		if err != nil {
			t.Fatalf("ValueFromTerraform(%v): %v", in, err)
		}
		xv, ok := v.(XMLValue)
		if !ok {
			t.Fatalf("value type = %T; want XMLValue", v)
		}
		out, err := xv.ToTerraformValue(ctx)
		if err != nil {
			t.Fatalf("ToTerraformValue: %v", err)
		}
		if !out.Equal(in) {
			t.Errorf("round trip = %v; want %v", out, in)
		}
		if !xv.Type(ctx).Equal(typ) {
			t.Errorf("Type = %v", xv.Type(ctx))
		}
	}
	if typ.Equal(types.StringType) {
		t.Error("XMLType must not equal StringType")
	}
	if _, ok := typ.ValueType(ctx).(XMLValue); !ok {
		t.Error("ValueType is not an XMLValue")
	}
}

// NewXMLNull returns a null XMLValue.
func NewXMLNull() XMLValue { return XMLValue{StringValue: basetypes.NewStringNull()} }

// NewXMLUnknown returns an unknown XMLValue.
func NewXMLUnknown() XMLValue { return XMLValue{StringValue: basetypes.NewStringUnknown()} }
