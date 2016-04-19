/*-
 * Copyright 2016 Zbigniew Mandziejewicz
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

import "gopkg.in/square/go-jose.v2"

// JSONWebToken represents JSON Web Token as indicated in RFC7519
type JSONWebToken struct {
	payload func(k interface{}) ([]byte, error)
}

// Claims deserializes JSONWebToken payload into dest using provided key
func (t *JSONWebToken) Claims(dest interface{}, key interface{}) error {
	b, err := t.payload(key)
	if err != nil {
		return err
	}
	return unmarshalClaims(b, dest)
}

// ParseSigned parses token from JWS form
func ParseSigned(s string) (_ *JSONWebToken, err error) {
	sig, err := jose.ParseSigned(s)
	if err != nil {
		return
	}

	return &JSONWebToken{sig.Verify}, nil
}

// ParseEncrypted parses token from JWE form
func ParseEncrypted(s string) (_ *JSONWebToken, err error) {
	enc, err := jose.ParseEncrypted(s)
	if err != nil {
		return
	}

	return &JSONWebToken{enc.Decrypt}, nil
}
