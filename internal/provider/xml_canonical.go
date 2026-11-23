package provider

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// utf8BOM is the UTF-8 byte order mark (U+FEFF) some editors put in front of a
// policy file.
const utf8BOM = "\xef\xbb\xbf"

// serverTenantObjectIDAttr is the root attribute B2C adds to every stored
// policy. It is left out of the canonical form so a stored policy compares
// equal to the document that was uploaded.
const serverTenantObjectIDAttr = "TenantObjectId"

// xmlNamespaceURL is the namespace the decoder resolves the xml prefix to.
const xmlNamespaceURL = "http://www.w3.org/XML/1998/namespace"

// xmlFrame is the state of an open element during canonicalisation.
type xmlFrame struct {
	hasChild bool // a child element has been seen
	preserve bool // xml:space="preserve" is in effect
}

// canonicalXML returns a canonical form of an XML document, used to compare two
// documents for semantic equality. It drops the XML declaration and comments,
// resolves namespace prefixes to namespace names, and sorts each element's
// attributes by namespace and local name. Whitespace-only character data is
// dropped in an element with child elements, unless xml:space="preserve" is in
// effect, and kept in an element without child elements. Text content that is
// not whitespace-only is kept as is. A malformed document, one
// with no root element, more than one root element or text outside the root is
// an error.
func canonicalXML(doc string) (string, error) {
	dec := newXMLDecoder(doc)

	var out, text strings.Builder
	var stack []xmlFrame
	depth, roots := 0, 0

	// flush writes the pending character data. Whitespace-only data is kept in
	// a leaf element or where xml:space="preserve" is in effect, and dropped
	// otherwise. leafEnd reports that the data is followed by the end tag of the
	// current element.
	flush := func(leafEnd bool) error {
		t := text.String()
		text.Reset()
		if depth == 0 {
			if isXMLWhitespace(t) {
				return nil
			}
			return errors.New("text outside the root element")
		}
		if t == "" {
			return nil
		}
		f := stack[len(stack)-1]
		if isXMLWhitespace(t) && !f.preserve && !(leafEnd && !f.hasChild) {
			return nil
		}
		return xml.EscapeText(&out, []byte(t))
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth > 0 {
				stack[len(stack)-1].hasChild = true
			}
			if err := flush(false); err != nil {
				return "", err
			}
			if depth == 0 {
				roots++
				if roots > 1 {
					return "", errors.New("more than one root element")
				}
			}
			preserve := depth > 0 && stack[len(stack)-1].preserve
			for _, a := range t.Attr {
				if a.Name.Local == "space" && (a.Name.Space == "xml" || a.Name.Space == xmlNamespaceURL) {
					switch a.Value {
					case "preserve":
						preserve = true
					case "default":
						preserve = false
					}
				}
			}
			stack = append(stack, xmlFrame{preserve: preserve})
			depth++
			out.WriteString("<")
			out.WriteString(canonicalName(t.Name))
			attrs := append([]xml.Attr(nil), t.Attr...)
			sort.SliceStable(attrs, func(i, j int) bool {
				if attrs[i].Name.Space != attrs[j].Name.Space {
					return attrs[i].Name.Space < attrs[j].Name.Space
				}
				return attrs[i].Name.Local < attrs[j].Name.Local
			})
			for _, a := range attrs {
				if depth == 1 && a.Name.Space == "" && a.Name.Local == serverTenantObjectIDAttr {
					continue
				}
				out.WriteString(" ")
				out.WriteString(canonicalName(a.Name))
				out.WriteString(`="`)
				if err := xml.EscapeText(&out, []byte(a.Value)); err != nil {
					return "", err
				}
				out.WriteString(`"`)
			}
			out.WriteString(">")
		case xml.EndElement:
			if err := flush(true); err != nil {
				return "", err
			}
			stack = stack[:len(stack)-1]
			depth--
			out.WriteString("</")
			out.WriteString(canonicalName(t.Name))
			out.WriteString(">")
		case xml.CharData:
			text.Write(t)
		case xml.Comment:
			// Comments are not significant.
		case xml.ProcInst:
			if t.Target == "xml" {
				continue // the XML declaration
			}
			if err := flush(false); err != nil {
				return "", err
			}
			out.WriteString("<?" + t.Target + " " + strings.TrimSpace(string(t.Inst)) + "?>")
		case xml.Directive:
			if err := flush(false); err != nil {
				return "", err
			}
			out.WriteString("<!" + string(t) + ">")
		}
	}
	if err := flush(false); err != nil {
		return "", err
	}
	if depth != 0 {
		return "", errors.New("unexpected end of document")
	}
	if roots == 0 {
		return "", errors.New("no root element")
	}
	return out.String(), nil
}

// xmlSemanticallyEqual reports whether two documents have the same canonical
// form. If either document cannot be canonicalised only identical strings are
// equal.
func xmlSemanticallyEqual(a, b string) bool {
	if a == b {
		return true
	}
	ca, errA := canonicalXML(a)
	cb, errB := canonicalXML(b)
	if errA != nil || errB != nil {
		return false
	}
	return ca == cb
}

// newXMLDecoder returns a strict decoder for doc. A leading byte order mark is
// skipped, and any declared encoding is read as is because Terraform strings
// are always UTF-8.
func newXMLDecoder(doc string) *xml.Decoder {
	dec := xml.NewDecoder(strings.NewReader(strings.TrimPrefix(doc, utf8BOM)))
	dec.Strict = true
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	return dec
}

// canonicalName formats a name as {namespace}local, or local without a namespace.
func canonicalName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return fmt.Sprintf("{%s}%s", n.Space, n.Local)
}

// isXMLWhitespace reports whether s holds only XML whitespace (space, tab, CR, LF).
func isXMLWhitespace(s string) bool {
	return strings.Trim(s, " \t\r\n") == ""
}
