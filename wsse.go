package wsse

import (
	"encoding/xml"

	"github.com/gosoap/xsd"
)

const Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

const (
	UsernameTokenProfilePasswordDigest = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"

	SOAPMessageSecurityBase64Binary = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

// AttributedString represents an element with arbitrary attributes
type AttributedString struct {
	ID xsd.String `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

// PasswordString is used for password elements per Section 4.1
type PasswordString struct { // extends AttributedString
	ID xsd.String `xml:",attr,omitempty"`

	Type xsd.AnyURI `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

func (o *PasswordString) UnmarshalText(text []byte) error {
	o.Value = string(text)
	return nil
}

// EncodedString is used for elements containing stringified binary data
type EncodedString struct { // extends AttributedString
	ID xsd.String `xml:",attr,omitempty"`

	Type xsd.AnyURI `xml:",attr,omitempty"`

	EncodingType xsd.AnyURI `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

// UsernameToken defines the wsse:UsernameToken element per Section 4.1
type UsernameToken struct {
	XMLName xml.Name `xml:"wsse:UsernameToken"`

	NS string `xml:"xmlns:wsse,attr,omitempty"`

	ID xsd.String `xml:",attr,omitempty"`

	Username AttributedString `xml:"wsse:Username"`

	EncodingType xsd.AnyURI `xml:",attr,omitempty"`

	Extra []interface{}
}

// BinarySecurityToken defines the wsse:BinarySecurityToken element per Section 4.2
type BinarySecurityToken struct {
	XMLName xml.Name `xml:"wsse:BinarySecurityToken"`

	NS string `xml:"xmlns:wsse,attr,omitempty"`

	ValueType xsd.AnyURI `xml:",attr,omitempty"`

	ID xsd.String `xml:",attr,omitempty"`

	EncodingType xsd.AnyURI `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

// Reference defines a security token reference
type Reference struct {
	XMLName xml.Name `xml:"wsse:Reference"`

	NS string `xml:"xmlns:wsse,attr,omitempty"`

	URI xsd.AnyURI `xml:",attr,omitempty"`

	ValueType xsd.AnyURI `xml:",attr,omitempty"`
}

// Embedded defines a security token embedded reference
type Embedded struct {
	XMLName xml.Name `xml:"wsse:Embedded"`

	NS string `xml:"xmlns:wsse,attr,omitempty"`

	ValueType xsd.AnyURI `xml:",attr,omitempty"`

	Extra []interface{}
}

type Password struct {
	XMLName xml.Name `xml:"wsse:Password"`

	ID xsd.String `xml:",attr,omitempty"`

	Type xsd.AnyURI `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}

type Nonce struct {
	XMLName xml.Name `xml:"wsse:Nonce"`

	ID xsd.String `xml:",attr,omitempty"`

	Type xsd.AnyURI `xml:",attr,omitempty"`

	EncodingType xsd.AnyURI `xml:",attr,omitempty"`

	Value string `xml:",chardata"`
}
