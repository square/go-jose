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

var (
	sharedKey                    = []byte("secret")
	sharedEncryptionKey          = []byte("itsa16bytesecret")
	signedToken                  = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwic2NvcGVzIjpbInMxIiwiczIiXX0.Y6_PfQHrzRJ_Vlxij5VI07-pgDIuJNN3Z_g5sSaGQ0c`
	invalidPayloadSignedToken    = `eyJhbGciOiJIUzI1NiJ9.aW52YWxpZC1wYXlsb2Fk.ScBKKm18jcaMLGYDNRUqB5gVMRZl4DM6dh3ShcxeNgY`
	invalidPartsSignedToken      = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwic2NvcGVzIjpbInMxIiwiczIiXX0`
	encryptedToken               = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..NZrU98U4QNO0y-u6.HSq5CvlmkUT1BPqLGZ4.1-zuiZ4RbHrTTUoA8Dvfhg`
	invalidPayloadEncryptedToken = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..T4jCS4Yyw1GCH0aW.y4gFaMITdBs_QZM8RKrL.6MPyk1cMVaOJFoNGlEuaRQ`
	invalidPartsEncryptedToken   = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..NZrU98U4QNO0y-u6.HSq5CvlmkUT1BPqLGZ4`
)

type customClaims struct {
	Scopes []string `json:"scopes,omitempty"`
}

func TestDecodeToken(t *testing.T) {
	tok, err := ParseSigned(signedToken)
	if assert.NoError(t, err, "Error parsing signed token.") {
		c := &Claims{}
		c2 := &customClaims{}
		if assert.NoError(t, tok.Claims(sharedKey, c, c2)) {
			assert.Equal(t, "subject", c.Subject)
			assert.Equal(t, "issuer", c.Issuer)
			assert.Equal(t, []string{"s1", "s2"}, c2.Scopes)
		}
	}

	assert.EqualError(t, tok.Claims([]byte("invalid-secret")), "square/go-jose: error in cryptographic primitive")

	tok2, err := ParseSigned(invalidPayloadSignedToken)
	if assert.NoError(t, err, "Error parsing signed token.") {
		assert.Error(t, tok2.Claims(sharedKey, &Claims{}), "Expected unmarshaling claims to fail.")
	}

	_, err = ParseSigned(invalidPartsSignedToken)
	assert.EqualError(t, err, "square/go-jose: compact JWS format must have three parts")

	tok3, err := ParseEncrypted(encryptedToken)
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		c := &Claims{}
		if assert.NoError(t, tok3.Claims(sharedEncryptionKey, c)) {
			assert.Equal(t, "foo", c.Subject)
		}
	}

	assert.EqualError(t, tok3.Claims([]byte("invalid-secret-key")), "square/go-jose: error in cryptographic primitive")

	tok4, err := ParseEncrypted(invalidPayloadEncryptedToken)
	if assert.NoError(t, err, "Error parsing encrypted token.") {
		assert.Error(t, tok4.Claims(sharedEncryptionKey, &Claims{}))
	}

	_, err = ParseEncrypted(invalidPartsEncryptedToken)
	assert.EqualError(t, err, "square/go-jose: compact JWE format must have five parts")
}

func TestEncodeToken(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedKey}, &jose.SignerOptions{})
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
	if assert.NoError(t, tok.Claims(sharedKey, c3, c4)) {
		assert.Equal(t, "subject", c3.Subject)
		assert.Equal(t, "issuer", c3.Issuer)
		assert.Equal(t, []string{"s1", "s2"}, c4.Scopes)
	}
}
