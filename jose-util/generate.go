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
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/jose-util/generator"
)

func generate() {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var err error

	switch *generateUseFlag {
	case "sig":
		pubKey, privKey, err = generator.NewSigningKey(jose.SignatureAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
	case "enc":
		pubKey, privKey, err = generator.NewEncryptionKey(jose.KeyAlgorithm(*generateAlgFlag), *generateKeySizeFlag)
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
