/*-
 * Copyright 2019 Square Inc.
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

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	jose "github.com/square/go-jose/v3"
	"golang.org/x/crypto/ed25519"
)

// GenerateSigningKey generates a keypair for corresponding SignatureAlgorithm.
func GenerateSigningKey(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES256K, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256:  256,
			jose.ES256K: 256,
			jose.ES384:  384,
			jose.ES512:  521, // sic!
			jose.EdDSA:  256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("invalid elliptic curve key size, this algorithm does not support arbitrary size")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("invalid key size for RSA key, 2048 or more is required")
		}
	}
	switch alg {
	case jose.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ES256K:
		key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	default:
		return nil, nil, fmt.Errorf("unknown algorithm %s for signing key", alg)
	}
}

// GenerateEncryptionKey generates a keypair for corresponding KeyAlgorithm.
func GenerateEncryptionKey(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("invalid key size for RSA key, 2048 or more is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("invalid elliptic curve key size, use one of 256, 384, or 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	default:
		return nil, nil, fmt.Errorf("unknown algorithm %s for encryption key", alg)
	}
}

func generate() {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var err error

	switch *generateUseFlag {
	case "sig":
		pubKey, privKey, err = GenerateSigningKey(jose.SignatureAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
	case "enc":
		pubKey, privKey, err = GenerateEncryptionKey(jose.KeyAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
	default:
		// According to RFC 7517 section-8.2.  This is unlikely to change in the
		// near future. If it were, new values could be found in the registry under
		// "JSON Web Key Use": https://www.iana.org/assignments/jose/jose.xhtml
		app.FatalIfError(errors.New("invalid key use.  Must be \"sig\" or \"enc\""), "unable to generate key")
	}
	app.FatalIfError(err, "unable to generate key")

	kid := *generateKeyIdentFlag

	priv := jose.JSONWebKey{Key: privKey, KeyID: kid, Algorithm: *generateAlgFlag, Use: *generateUseFlag}

	// Generate a canonical kid based on RFC 7638
	if kid == "" {
		thumb, err := priv.Thumbprint(crypto.SHA256)
		app.FatalIfError(err, "unable to compute thumbprint")

		kid = base64.URLEncoding.EncodeToString(thumb)
		priv.KeyID = kid
	}

	// I'm not sure why we couldn't use `pub := priv.Public()` here as the private
	// key should contain the public key.  In case for some reason it doesn't,
	// this builds a public JWK from scratch.
	pub := jose.JSONWebKey{Key: pubKey, KeyID: kid, Algorithm: *generateAlgFlag, Use: *generateUseFlag}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		app.Fatalf("invalid keys were generated")
	}

	privJSON, err := priv.MarshalJSON()
	app.FatalIfError(err, "failed to marshal private key to JSON")
	pubJSON, err := pub.MarshalJSON()
	app.FatalIfError(err, "failed to marshal public key to JSON")

	name := fmt.Sprintf("jwk-%s-%s", *generateUseFlag, kid)
	pubFile := fmt.Sprintf("%s-pub.json", name)
	privFile := fmt.Sprintf("%s-priv.json", name)

	err = writeNewFile(pubFile, pubJSON, 0444)
	app.FatalIfError(err, "error on write to file %s", pubFile)

	err = writeNewFile(privFile, privJSON, 0400)
	app.FatalIfError(err, "error on write to file %s", privFile)
}
