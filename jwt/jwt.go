package jwt

import "github.com/square/go-jose"

type JSONWebToken struct {
	Claims  Claims
	payload []byte
}

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

func (t *JSONWebToken) ParsePrivate(dest interface{}) error {
	return jose.UnmarshalJSON(t.payload, dest)
}
