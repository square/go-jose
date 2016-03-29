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
	"reflect"

	"github.com/square/go-jose"
)

// JSONWebToken represents JSON Web Token as indicated in RFC7519
type JSONWebToken struct {
	payload []byte
}

// New constructs JSONWebToken containing given claims
func New(claims interface{}) (*JSONWebToken, error) {
	t := reflect.TypeOf(claims)
	if t.Kind() != reflect.Map || (t.Kind() == reflect.Ptr && t.Elem().Kind() != reflect.Struct) {
		return nil, ErrInvalidClaims
	}

	b, err := marshalClaims(claims)
	if err != nil {
		return nil, err
	}
	return &JSONWebToken{b}, nil
}

// Claims deserializes JSONWebToken payload into given dest
func (t *JSONWebToken) Claims(dest interface{}) error {
	return unmarshalClaims(t.payload, dest)
}

// Encrypt converts token payload into JSONWebEncryption
func (t JSONWebToken) Encrypt(e jose.Encrypter) (*jose.JSONWebEncryption, error) {
	return e.Encrypt(t.payload)
}

// Sign converts token payload into JSONWebSignature
func (t JSONWebToken) Sign(e jose.Signer) (*jose.JSONWebSignature, error) {
	return e.Sign(t.payload)
}

// ParseSigned parses token from JWS form
func ParseSigned(s string, key interface{}) (_ *JSONWebToken, err error) {
	sig, err := jose.ParseSigned(s)
	if err != nil {
		return
	}

	p, err := sig.Verify(key)
	if err != nil {
		return
	}

	return &JSONWebToken{p}, nil
}

// ParseEncrypted parses token from JWE form
func ParseEncrypted(s string, key interface{}) (_ *JSONWebToken, err error) {
	enc, err := jose.ParseEncrypted(s)
	if err != nil {
		return
	}

	p, err := enc.Decrypt(key)
	if err != nil {
		return
	}

	return &JSONWebToken{p}, nil
}
