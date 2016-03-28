/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"time"

	"github.com/square/go-jose"
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

type rawClaims struct {
	Iss string        `json:"iss,omitempty"`
	Sub string        `json:"sub,omitempty"`
	Aud StringOrArray `json:"aud,omitempty"`
	Exp NumericDate   `json:"exp,omitempty"`
	Nbf NumericDate   `json:"nbf,omitempty"`
	Iat NumericDate   `json:"iat,omitempty"`
	Jti string        `json:"jti,omitempty"`
}

func (c *Claims) MarshalJSON() ([]byte, error) {
	t := rawClaims{
		Iss: c.Issuer,
		Sub: c.Subject,
		Aud: StringOrArray(c.Audience),
		Exp: TimeToNumericDate(c.Expiry),
		Nbf: TimeToNumericDate(c.NotBefore),
		Iat: TimeToNumericDate(c.IssuedAt),
		Jti: c.ID,
	}

	b, err := jose.MarshalJSON(t)

	if err != nil {
		return nil, err
	}

	return b, err
}

func (c *Claims) UnmarshalJSON(b []byte) error {
	t := rawClaims{}

	if err := jose.UnmarshalJSON(b, &t); err != nil {
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
