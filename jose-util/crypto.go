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

import jose "github.com/square/go-jose"

func encrypt() {
	pub, err := LoadPublicKey(keyBytes())
	exitOnError(err, "unable to read public key")

	alg := jose.KeyAlgorithm(*encryptAlgFlag)
	enc := jose.ContentEncryption(*encryptEncFlag)

	crypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: pub}, nil)
	exitOnError(err, "unable to instantiate encrypter")

	obj, err := crypter.Encrypt(readInput(*inFile))
	exitOnError(err, "unable to encrypt")

	var msg string
	if *encryptFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		exitOnError(err, "unable to serialize message")
	}

	writeOutput(*outFile, []byte(msg))
}

func decrypt() {
	priv, err := LoadPrivateKey(keyBytes())
	exitOnError(err, "unable to read private key")

	obj, err := jose.ParseEncrypted(string(readInput(*inFile)))
	exitOnError(err, "unable to parse message")

	plaintext, err := obj.Decrypt(priv)
	exitOnError(err, "unable to decrypt message")

	writeOutput(*outFile, plaintext)
}

func sign() {
	signingKey, err := LoadPrivateKey(keyBytes())
	exitOnError(err, "unable to read private key")

	alg := jose.SignatureAlgorithm(*signAlgFlag)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, nil)
	exitOnError(err, "unable to make signer")

	obj, err := signer.Sign(readInput(*inFile))
	exitOnError(err, "unable to sign")

	var msg string
	if *signFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		exitOnError(err, "unable to serialize message")
	}

	writeOutput(*outFile, []byte(msg))
}

func verify() {
	verificationKey, err := LoadPublicKey(keyBytes())
	exitOnError(err, "unable to read public key")

	obj, err := jose.ParseSigned(string(readInput(*inFile)))
	exitOnError(err, "unable to parse message")

	plaintext, err := obj.Verify(verificationKey)
	exitOnError(err, "invalid signature")

	writeOutput(*outFile, plaintext)
}
