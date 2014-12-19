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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// LoadPublicKey loads a public key from PEM/DER-encoded data.
func LoadPublicKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err := x509.ParsePKIXPublicKey(input)
	if err == nil {
		return pub, nil
	}

	cert, err := x509.ParseCertificate(input)
	if err == nil {
		return cert.PublicKey, nil
	}

	return nil, errors.New("square/go-jose: unable to parse public key")
}

// LoadPrivateKey loads a private key from PEM/DER-encoded data.
func LoadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err := x509.ParsePKCS1PrivateKey(input)
	if err == nil {
		return priv, nil
	}

	priv, err = x509.ParsePKCS8PrivateKey(input)
	if err == nil {
		return priv, nil
	}

	priv, err = x509.ParseECPrivateKey(input)
	if err == nil {
		return priv, nil
	}

	return nil, errors.New("square/go-jose: unable to parse private key")
}

// Build big int from base64-encoded string.
func parseBigInt(input interface{}) (*big.Int, error) {
	val, err := base64URLDecode(input)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(val), nil
}

// parseECPublicKey loads an elliptic curve public key from a JWK object.
func parseECPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"]
	if kty != "EC" {
		return nil, fmt.Errorf("square/go-jose: expecting EC key, found '%s' instead", kty)
	}

	crv, _ := jwk["crv"]

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported elliptic curve '%s'", crv)
	}

	rawX, xPresent := jwk["x"]
	rawY, yPresent := jwk["y"]

	if !xPresent || !yPresent {
		return nil, fmt.Errorf("square/go-jose: invalid EC key, missing x/y values")
	}

	x, err := parseBigInt(rawX)
	if err != nil {
		return nil, err
	}

	y, err := parseBigInt(rawY)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// serializeECPublicKey loads an elliptic curve public key from a JWK object.
func serializeECPublicKey(key *ecdsa.PublicKey) (map[string]interface{}, error) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"x":   base64URLEncode(key.X.Bytes()),
		"y":   base64URLEncode(key.Y.Bytes()),
	}

	switch key.Curve {
	case elliptic.P256():
		jwk["crv"] = "P-256"
	case elliptic.P384():
		jwk["crv"] = "P-384"
	case elliptic.P521():
		jwk["crv"] = "P-521"
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}

	return jwk, nil
}
