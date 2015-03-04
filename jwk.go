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
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
)

// rawJsonWebKey represents a public or private key in JWK format, used for parsing/serializing.
type rawJsonWebKey struct {
	// TODO(cs): Add support for private keys.
	Kty string      `json:"kty,omitempty"`
	Crv string      `json:"crv,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
}

// JsonWebKey represents a public or private key in JWK format.
type JsonWebKey struct {
	key interface{}
}

func (k *JsonWebKey) MarshalJSON() ([]byte, error) {
	var raw rawJsonWebKey
	switch key := k.key.(type) {
	case *ecdsa.PublicKey:
		raw.fromEcPublicKey(key)
	case *rsa.PublicKey:
		raw.fromRsaPublicKey(key)
	default:
		return nil, fmt.Errorf("square/go-jose: unkown key type '%s'", reflect.TypeOf(key))
	}

	return json.Marshal(raw)
}

func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	var raw rawJsonWebKey
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	var key interface{} = nil
	switch raw.Kty {
	case "EC":
		key, err = raw.ecPublicKey()
	case "RSA":
		key, err = raw.rsaPublicKey()
	default:
		err = fmt.Errorf("square/go-jose: unkown json web key type '%s'", raw.Kty)
	}

	if err == nil {
		*k = JsonWebKey{key: key}
	}
	return
}

func (key rawJsonWebKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if key.N == nil || key.E == nil {
		return nil, fmt.Errorf("square/go-jose: invalid RSA key, missing n/e values")
	}

	return &rsa.PublicKey{
		N: key.N.bigInt(),
		E: key.E.toInt(),
	}, nil
}

func (key *rawJsonWebKey) fromRsaPublicKey(pub *rsa.PublicKey) {
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e, uint32(pub.E))

	*key = rawJsonWebKey{
		Kty: "RSA",
		N:   newBuffer(pub.N.Bytes()),
		E:   newBuffer(e),
	}
}

func (key rawJsonWebKey) ecPublicKey() (*ecdsa.PublicKey, error) {
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
