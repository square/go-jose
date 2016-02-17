package claims

import (
	"encoding/json"
	"time"
)

const (

	// Audience identifies the target audience, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#audDef
	Audience = "aud"

	// Expires identifies the time after which the token must not be accepted, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#expDef
	Expires = "exp"

	// IssuedAt identifies the time the token was issued at, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#iatDef
	IssuedAt = "iat"

	// Issuer identifies the principal who created the token, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#issDef
	Issuer = "iss"

	// JwtID identifies this token uniquely, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#jtiDef
	JwtID = "jti"

	// NotBefore identifies the time after which this token becomes valid, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef
	NotBefore = "nbf"

	// Subject identifies the principal this token is intended for, see https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#subDef
	Subject = "sub"
)

// Assertion verifies a given Claims value
type Assertion interface {
	Verify(claim Claim, value interface{}) error
}

type (
	// Assertions maps a Claim to a number of matching Assertions
	Assertions map[Claim][]Assertion

	// Claim identifies a reserved (well-known) claim
	Claim string

	// Claims maps a Claim to it's value
	Claims map[Claim]interface{}
)

// NewClaims initializes a serializable Claims structure
func NewClaims() (claims Claims) {
	claims = make(map[Claim]interface{})
	return claims
}

// Bytes serializes the Claims to JSON
func (c Claims) Bytes() []byte {

	out, err := c.MarshalBinary()

	if err != nil {
		panic(err)
	}

	return out

}

// Add adds a Claim and associated value to the Claims, returning the Claims
func (c Claims) Add(claim Claim, value interface{}) Claims {
	c[claim] = value
	return c
}

// Expires adds an expiry claim as UTC integer
func (c Claims) Expires(t time.Time) Claims {
	return c.Add(Expires, c.t2i(t))
}

// IssuedAt adds an issued at claim as UTC integer
func (c Claims) IssuedAt(t time.Time) Claims {
	return c.Add(IssuedAt, c.t2i(t))
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (c Claims) MarshalBinary() ([]byte, error) {
	return json.Marshal(c)
}

// NotBefore adds an not before claim as UTC integer
func (c Claims) NotBefore(t time.Time) Claims {
	return c.Add(NotBefore, c.t2i(t))
}

func (c Claims) t2i(t time.Time) int {
	return int(t.UTC().Unix())
}
