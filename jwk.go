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

package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

// rawJsonWebKey represents a public or private key in JWK format, used for parsing/serializing.
type rawJsonWebKey struct {
	// TODO(cs): Add support for private keys, non-EC keys.
	Kty string      `json:"kty,omitempty"`
	Crv string      `json:"crv,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
}

func (key *rawJsonWebKey) ecPublicKey() (*ecdsa.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("square/go-jose: expecting public key, found nil")
	}

	if key.Kty != "EC" {
		return nil, fmt.Errorf("square/go-jose: expecting EC key, found '%s' instead", key.Kty)
	}

	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported elliptic curve '%s'", key.Crv)
	}

	if key.X == nil || key.Y == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC key, missing x/y values")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     key.X.bigInt(),
		Y:     key.Y.bigInt(),
	}, nil
}

// serializeECPublicKey loads an elliptic curve public key from a JWK object.
func (key *rawJsonWebKey) fromEcPublicKey(pub *ecdsa.PublicKey) error {
	*key = rawJsonWebKey{
		Kty: "EC",
		X:   newBuffer(pub.X.Bytes()),
		Y:   newBuffer(pub.Y.Bytes()),
	}

	switch pub.Curve {
	case elliptic.P256():
		key.Crv = "P-256"
	case elliptic.P384():
		key.Crv = "P-384"
	case elliptic.P521():
		key.Crv = "P-521"
	default:
		return fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}

	return nil
}
