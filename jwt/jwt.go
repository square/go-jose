package jwt

import "github.com/square/go-jose"

// JSONWebToken represents JSON Web Token as indicated in RFC7519
type JSONWebToken struct {
	Claims  Claims
	payload []byte
}

// ParseSigned parses token from JWS form
func ParseSigned(s string, key interface{}) (t *JSONWebToken, err error) {
	sig, err := jose.ParseSigned(s)
	if err != nil {
		return
	}

	p, err := sig.Verify(key)
	if err != nil {
		return
	}

	c := Claims{}
	if err = jose.UnmarshalJSON(p, &c); err != nil {
		return
	}

	return &JSONWebToken{c, p}, nil
}

// ParseEncrypted parses token from JWE form
func ParseEncrypted(s string, key interface{}) (t *JSONWebToken, err error) {
	enc, err := jose.ParseEncrypted(s)
	if err != nil {
		return
	}

	p, err := enc.Decrypt(key)
	if err != nil {
		return
	}

	c := Claims{}
	if err = jose.UnmarshalJSON(p, &c); err != nil {
		return
	}

	return &JSONWebToken{c, p}, nil
}

// ParsePrivate parses private claims from JSONWebToken payload
func (t *JSONWebToken) ParsePrivate(dest interface{}) error {
	return jose.UnmarshalJSON(t.payload, dest)
}
