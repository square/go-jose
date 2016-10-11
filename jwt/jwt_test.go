/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

var encryptionKey = []byte("secret")
var rawToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwic2NvcGVzIjpbInMxIiwiczIiXX0.Y6_PfQHrzRJ_Vlxij5VI07-pgDIuJNN3Z_g5sSaGQ0c`

type customClaims struct {
	Scopes []string `json:"scopes,omitempty"`
}

func TestDecodeToken(t *testing.T) {
	tok, err := ParseSigned(rawToken)
	assert.NoError(t, err)
	c := &Claims{}
	c2 := &customClaims{}
	if assert.NoError(t, tok.Claims(encryptionKey, c, c2)) {
		assert.Equal(t, c.Subject, "subject")
		assert.Equal(t, c.Issuer, "issuer")
		assert.Equal(t, c2.Scopes, []string{"s1", "s2"})
	}
}

func TestEncodeToken(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: encryptionKey}, &jose.SignerOptions{})
	require.NoError(t, err)

	c := &Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	c2 := &customClaims{
		Scopes: []string{"s1", "s2"},
	}

	raw, err := Signed(signer).Claims(c).Claims(c2).CompactSerialize()
	require.NoError(t, err)

	tok, err := ParseSigned(raw)
	require.NoError(t, err)

	c3 := &Claims{}
	c4 := &customClaims{}
	if assert.NoError(t, tok.Claims(encryptionKey, c3, c4)) {
		assert.Equal(t, "subject", c3.Subject)
		assert.Equal(t, "issuer", c3.Issuer)
		assert.Equal(t, []string{"s1", "s2"}, c4.Scopes)
	}
}

func TestInvalidSignedTokens(t *testing.T) {

}

func TestInvalidEncryptedTokens(t *testing.T) {

}
