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
	"encoding/json"
	"reflect"

	"github.com/fatih/structs"
	"gopkg.in/square/go-jose.v2"
)

// Builder is a utility for making JSON Web Tokens. Calls can be chained, and
// errors are accumulated until the final call to CompactSerialize/FullSerialize.
type Builder interface {
	PublicClaims(c Claims) Builder
	PrivateClaims(i interface{}) Builder
	// Token builds a JSONWebToken from provided data.
	Token() (*JSONWebToken, error)
	// FullSerialize serializes a token using the full serialization format.
	FullSerialize() (string, error)
	// CompactSerialize serializes a token using the compact serialization format.
	CompactSerialize() (string, error)
}

type builder struct {
	payload map[string]interface{}
	err     error
}

type signedBuilder struct {
	builder
	sig jose.Signer
}

type encryptedBuilder struct {
	builder
	enc jose.Encrypter
}

// Signed creates builder for signed tokens.
func Signed(sig jose.Signer) Builder {
	return &signedBuilder{
		sig: sig,
	}
}

// Encrypted creates builder for encrypted tokens.
func Encrypted(enc jose.Encrypter) Builder {
	return &encryptedBuilder{
		enc: enc,
	}
}

func (b builder) PublicClaims(c Claims) builder {
	return b.merge(structs.Map(c))
}

func (b builder) PrivateClaims(i interface{}) builder {
	if b.err != nil {
		return b
	}

	if v, ok := i.(map[string]interface{}); ok {
		return b.merge(v)
	}

	if v := reflect.Indirect(reflect.ValueOf(i)); v.Kind() != reflect.Struct {
		return builder{
			err: ErrInvalidClaims,
		}
	}

	return b.merge(structs.Map(i))
}

func (b *builder) merge(m map[string]interface{}) builder {
	var p map[string]interface{}
	for k, v := range b.payload {
		p[k] = v
	}
	for k, v := range m {
		p[k] = v
	}

	return builder{
		payload: p,
	}
}

func (b *builder) Token(p func(interface{}) ([]byte, error), h []jose.Header) (*JSONWebToken, error) {
	return &JSONWebToken{
		payload: p,
		Headers: h,
	}, nil
}

func (b *signedBuilder) PublicClaims(c Claims) Builder {
	return &signedBuilder{
		builder: b.builder.PublicClaims(c),
		sig:     b.sig,
	}
}

func (b *signedBuilder) PrivateClaims(i interface{}) Builder {
	return &signedBuilder{
		builder: b.builder.PrivateClaims(i),
		sig:     b.sig,
	}
}

func (b *signedBuilder) Token() (*JSONWebToken, error) {
	sig, err := b.sign()
	if err != nil {
		return nil, err
	}

	h := make([]jose.Header, len(sig.Signatures))
	for i, v := range sig.Signatures {
		h[i] = v.Header
	}

	return b.builder.Token(sig.Verify, h)
}

func (b *signedBuilder) CompactSerialize() (string, error) {
	sig, err := b.sign()
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}

func (b *signedBuilder) FullSerialize() (string, error) {
	sig, err := b.sign()
	if err != nil {
		return "", err
	}

	return sig.FullSerialize(), nil
}

func (b *signedBuilder) sign() (*jose.JSONWebSignature, error) {
	if b.err != nil {
		return nil, b.err
	}

	p, err := json.Marshal(b.payload)
	if err != nil {
		return nil, err
	}

	return b.sig.Sign(p)
}

func (b *encryptedBuilder) PublicClaims(c Claims) Builder {
	return &encryptedBuilder{
		builder: b.builder.PublicClaims(c),
		enc:     b.enc,
	}
}

func (b *encryptedBuilder) PrivateClaims(i interface{}) Builder {
	return &encryptedBuilder{
		builder: b.builder.PrivateClaims(i),
		enc:     b.enc,
	}
}

func (b *encryptedBuilder) CompactSerialize() (string, error) {
	enc, err := b.encrypt()
	if err != nil {
		return "", err
	}

	return enc.CompactSerialize()
}

func (b *encryptedBuilder) FullSerialize() (string, error) {
	enc, err := b.encrypt()
	if err != nil {
		return "", err
	}

	return enc.FullSerialize(), nil
}

func (b *encryptedBuilder) Token() (*JSONWebToken, error) {
	enc, err := b.encrypt()
	if err != nil {
		return nil, err
	}

	return b.builder.Token(enc.Decrypt, []jose.Header{enc.Header})
}

func (b *encryptedBuilder) encrypt() (*jose.JSONWebEncryption, error) {
	if b.err != nil {
		return nil, b.err
	}

	p, err := json.Marshal(b.payload)
	if err != nil {
		return nil, err
	}

	return b.enc.Encrypt(p)
}
