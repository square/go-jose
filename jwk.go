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
	"crypto"
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
	Alg string      `json:"alg,omitempty"`
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
	Key       interface{}
	KeyID     string
	Algorithm string
}

// MarshalJSON serializes the given key to its JSON representation.
func (k JsonWebKey) MarshalJSON() ([]byte, error) {
	var raw *rawJsonWebKey
	var err error

	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		raw, err = fromEcPublicKey(key)
	case *rsa.PublicKey:
		raw = fromRsaPublicKey(key)
	case *ecdsa.PrivateKey:
		raw, err = fromEcPrivateKey(key)
	case *rsa.PrivateKey:
		raw, err = fromRsaPrivateKey(key)
	default:
		return nil, fmt.Errorf("square/go-jose: unkown key type '%s'", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, err
	}

	raw.Kid = k.KeyID
	raw.Alg = k.Algorithm

	return json.Marshal(raw)
}

// UnmarshalJSON reads a key from its JSON representation.
func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	var raw rawJsonWebKey
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	var key interface{}
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
		*k = JsonWebKey{Key: key, KeyID: raw.Kid, Algorithm: raw.Alg}
	}
	return
}

const rsaThumbprintTemplate = `{"e":"%s","kty":"RSA","n":"%s"}`
const ecThumbprintTemplate = `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`

func ecThumbprintInput(key *ecdsa.PublicKey) (string, error) {
	crv := ""
	coordLength := 0
	switch key.Curve {
	case elliptic.P256():
		crv = "P-256"
		coordLength = 32
	case elliptic.P384():
		crv = "P-384"
		coordLength = 48
	case elliptic.P521():
		crv = "P-521"
		coordLength = 66
	default:
		return "", fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}

	return fmt.Sprintf(ecThumbprintTemplate, crv,
		newZeroPaddedBuffer(key.X.Bytes(), coordLength).base64(),
		newZeroPaddedBuffer(key.Y.Bytes(), coordLength).base64()), nil
}

func rsaThumbprintInput(key *rsa.PublicKey) (string, error) {
	return fmt.Sprintf(rsaThumbprintTemplate,
		newBuffer(big.NewInt(int64(key.E)).Bytes()).base64(),
		newBuffer(key.N.Bytes()).base64()), nil
}

// Thumbprint computes the JWK Thumbprint of a key using the
// indicated hash algorithm.
func (k *JsonWebKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var input string
	var err error
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		input, err = ecThumbprintInput(key)
	case *rsa.PublicKey:
		input, err = rsaThumbprintInput(key)
	case *ecdsa.PrivateKey:
		input, err = ecThumbprintInput(key.Public().(*ecdsa.PublicKey))
	case *rsa.PrivateKey:
		input, err = rsaThumbprintInput(key.Public().(*rsa.PublicKey))
	default:
		return nil, fmt.Errorf("square/go-jose: unkown key type '%s'", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write([]byte(input))
	return h.Sum(nil), nil
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

func fromRsaPublicKey(pub *rsa.PublicKey) *rawJsonWebKey {
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e, uint32(pub.E))

	return &rawJsonWebKey{
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

func fromEcPublicKey(pub *ecdsa.PublicKey) (*rawJsonWebKey, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC key")
	}

	crv := ""
	coordLength := 0
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
		coordLength = 32
	case elliptic.P384():
		crv = "P-384"
		coordLength = 48
	case elliptic.P521():
		crv = "P-521"
		coordLength = 66
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}

	key := &rawJsonWebKey{
		Kty: "EC",
		Crv: crv,
		X:   newZeroPaddedBuffer(pub.X.Bytes(), coordLength),
		Y:   newZeroPaddedBuffer(pub.Y.Bytes(), coordLength),
	}

	return key, nil
}

func (key rawJsonWebKey) rsaPrivateKey() (*rsa.PrivateKey, error) {
	if key.N == nil || key.E == nil || key.D == nil || key.P == nil || key.Q == nil {
		return nil, fmt.Errorf("square/go-jose: invalid RSA private key, missing values")
	}

	rv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: key.N.bigInt(),
			E: key.E.toInt(),
		},
		D: key.D.bigInt(),
		Primes: []*big.Int{
			key.P.bigInt(),
			key.Q.bigInt(),
		},
	}

	if key.Dp != nil {
		rv.Precomputed.Dp = key.Dp.bigInt()
	}
	if key.Dq != nil {
		rv.Precomputed.Dq = key.Dq.bigInt()
	}
	if key.Qi != nil {
		rv.Precomputed.Qinv = key.Qi.bigInt()
	}

	err := rv.Validate()
	return rv, err
}

func fromRsaPrivateKey(rsa *rsa.PrivateKey) (*rawJsonWebKey, error) {
	if len(rsa.Primes) != 2 {
		return nil, ErrUnsupportedKeyType
	}

	raw := fromRsaPublicKey(&rsa.PublicKey)

	raw.D = newBuffer(rsa.D.Bytes())
	raw.P = newBuffer(rsa.Primes[0].Bytes())
	raw.Q = newBuffer(rsa.Primes[1].Bytes())

	return raw, nil
}

func (key rawJsonWebKey) ecPrivateKey() (*ecdsa.PrivateKey, error) {
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

	if key.X == nil || key.Y == nil || key.D == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC private key, missing x/y/d values")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     key.X.bigInt(),
			Y:     key.Y.bigInt(),
		},
		D: key.D.bigInt(),
	}, nil
}

func fromEcPrivateKey(ec *ecdsa.PrivateKey) (*rawJsonWebKey, error) {
	raw, err := fromEcPublicKey(&ec.PublicKey)
	if err != nil {
		return nil, err
	}

	if ec.D == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC private key")
	}

	raw.D = newBuffer(ec.D.Bytes())

	return raw, nil
}
