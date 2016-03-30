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

// Builder is an utility for making JSON Web Tokens
// Calls can be chained and the errors are accumulated till final call to
// CompactSerialize/FullSerialize allowing for single-line token creation
// Builder is immutable therefore it can be safely reused once created
type Builder struct {
	transform  func([]byte) (serializer, payload, error)
	payload    payload
	serializer serializer
	err        error
}

type payload func(interface{}) ([]byte, error)

type serializer interface {
	FullSerialize() string
	CompactSerialize() (string, error)
}

// New creates builder using provided Signer/Encrypter
func New(t interface{}) *Builder {
	switch t := t.(type) {
	case jose.Signer:
		return &Builder{
			transform: func(b []byte) (serializer, payload, error) {
				if s, err := t.Sign(b); err != nil {
					return nil, nil, err
				} else {
					return s, s.Verify, err
				}
			},
		}
	case jose.Encrypter:
		return &Builder{
			transform: func(b []byte) (serializer, payload, error) {
				if e, err := t.Encrypt(b); err != nil {
					return nil, nil, err
				} else {
					return e, e.Decrypt, err
				}
			},
		}
	default:
		panic("Expected Signer or Encrypter argument")
	}
}

// Claims encodes claims into JWE/JWS form
func (b *Builder) Claims(c interface{}) *Builder {
	if b.transform == nil {
		panic("Signer/Encrypter not set")
	}

	r := *b

	t := reflect.TypeOf(c)
	if t.Kind() != reflect.Map && (t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct) {
		r.err = ErrInvalidClaims
		return &r
	}

	raw, err := marshalClaims(c)
	if err != nil {
		r.err = err
		return &r
	}

	r.serializer, r.payload, r.err = r.transform(raw)
	return &r
}

func (b *Builder) Token() (*JSONWebToken, error) {
	if b.err != nil {
		return nil, b.err
	}

	if b.payload == nil {
		panic("Claims not set")
	}

	return &JSONWebToken{b.payload}, nil
}

// FullSerialize serializes an token using the full JSON serialization format
func (b *Builder) FullSerialize() (string, error) {
	if b.err != nil {
		return "", b.err
	}

	if b.serializer == nil {
		panic("Claims not set")
	}

	return b.serializer.FullSerialize(), nil
}

// CompactSerialize serializes an token using the compact serialization format
func (b *Builder) CompactSerialize() (string, error) {
	if b.err != nil {
		return "", b.err
	}

	if b.serializer == nil {
		panic("Claims not set")
	}

	return b.serializer.CompactSerialize()
}
