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
	"math/big"
	"reflect"
)

// rawJsonWebKey represents a public or private key in JWK format, used for parsing/serializing.
type rawJsonWebKey struct {
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *byteBuffer `json:"d,omitempty"`
	P  *byteBuffer `json:"p,omitempty"`
	Q  *byteBuffer `json:"q,omitempty"`
	Dp *byteBuffer `json:"dp,omitempty"`
	Dq *byteBuffer `json:"dq,omitempty"`
	Qi *byteBuffer `json:"qi,omitempty"`
}

// JsonWebKey represents a public or private key in JWK format.
type JsonWebKey struct {
	Key   interface{}
	KeyId string
}

func (k *JsonWebKey) MarshalJSON() ([]byte, error) {
	var raw rawJsonWebKey
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		raw.fromEcPublicKey(key)
	case *rsa.PublicKey:
		raw.fromRsaPublicKey(key)
	case *ecdsa.PrivateKey:
		err := raw.fromEcPrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		err := raw.fromRsaPrivateKey(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("square/go-jose: unkown key type '%s'", reflect.TypeOf(key))
	}

	raw.Kid = k.KeyId

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
		if raw.D != nil {
			key, err = raw.ecPrivateKey()
		} else {
			key, err = raw.ecPublicKey()
		}
	case "RSA":
		if raw.D != nil {
			key, err = raw.rsaPrivateKey()
		} else {
			key, err = raw.rsaPublicKey()
		}
	default:
		err = fmt.Errorf("square/go-jose: unkown json web key type '%s'", raw.Kty)
	}

	if err == nil {
		*k = JsonWebKey{Key: key, KeyId: raw.Kid}
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
	if pub == nil || pub.X == nil || pub.Y == nil {
		return fmt.Errorf("square/go-jose: invalid EC key")
	}

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

func (jwk rawJsonWebKey) rsaPrivateKey() (*rsa.PrivateKey, error) {
	if jwk.N == nil || jwk.E == nil || jwk.D == nil || jwk.P == nil || jwk.Q == nil {
		return nil, fmt.Errorf("square/go-jose: invalid RSA private key, missing values")
	}

	rv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: jwk.N.bigInt(),
			E: jwk.E.toInt(),
		},
		D: jwk.D.bigInt(),
		Primes: []*big.Int{
			jwk.P.bigInt(),
			jwk.Q.bigInt(),
		},
	}

	if jwk.Dp != nil {
		rv.Precomputed.Dp = jwk.Dp.bigInt()
	}
	if jwk.Dq != nil {
		rv.Precomputed.Dq = jwk.Dq.bigInt()
	}
	if jwk.Qi != nil {
		rv.Precomputed.Qinv = jwk.Qi.bigInt()
	}

	err := rv.Validate()
	return rv, err
}

func (jwkp *rawJsonWebKey) fromRsaPrivateKey(rsa *rsa.PrivateKey) error {
	if len(rsa.Primes) != 2 {
		return ErrUnsupportedKeyType
	}

	var jwk rawJsonWebKey
	jwk.fromRsaPublicKey(&rsa.PublicKey)

	jwk.D = newBuffer(rsa.D.Bytes())
	jwk.P = newBuffer(rsa.Primes[0].Bytes())
	jwk.Q = newBuffer(rsa.Primes[1].Bytes())
	*jwkp = jwk
	return nil
}

func (jwk rawJsonWebKey) ecPrivateKey() (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported elliptic curve '%s'", jwk.Crv)
	}

	if jwk.X == nil || jwk.Y == nil || jwk.D == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC private key, missing x/y/d values")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     jwk.X.bigInt(),
			Y:     jwk.Y.bigInt(),
		},
		D: jwk.D.bigInt(),
	}, nil
}

func (jwkp *rawJsonWebKey) fromEcPrivateKey(ec *ecdsa.PrivateKey) error {
	var jwk rawJsonWebKey

	err := jwk.fromEcPublicKey(&ec.PublicKey)
	if err != nil {
		return err
	}

	if ec.D == nil {
		return fmt.Errorf("square/go-jose: invalid EC private key")
	}

	jwk.D = newBuffer(ec.D.Bytes())
	*jwkp = jwk

	return nil
}
