package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	Expiry    time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	ID        string
}

type intermediate struct {
	Iss string        `json:"iss,omitempty"`
	Sub string        `json:"sub,omitempty"`
	Aud StringOrArray `json:"aud,omitempty"`
	Exp NumericDate   `json:"exp,omitempty"`
	Nbf NumericDate   `json:"nbf,omitempty"`
	Iat NumericDate   `json:"iat,omitempty"`
	Jti string        `json:"jti,omitempty"`
}

func (c *Claims) MarshalJSON() ([]byte, error) {
	t := intermediate{
		Iss: c.Issuer,
		Sub: c.Subject,
		Aud: StringOrArray(c.Audience),
		Exp: TimeToNumericDate(c.Expiry),
		Nbf: TimeToNumericDate(c.NotBefore),
		Iat: TimeToNumericDate(c.IssuedAt),
		Jti: c.ID,
	}

	fmt.Println(t)

	b := &bytes.Buffer{}
	e := json.NewEncoder(b)
	err := e.Encode(t)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), err
}

func (c *Claims) UnmarshalJSON(b []byte) error {
	t := intermediate{}

	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&t); err != nil {
		return err
	}

	c.Issuer = t.Iss
	c.Subject = t.Sub
	c.Audience = []string(t.Aud)
	c.Expiry = t.Exp.Time()
	c.NotBefore = t.Nbf.Time()
	c.IssuedAt = t.Iat.Time()
	c.ID = t.Jti

	return nil
}

func timeToInt(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}
