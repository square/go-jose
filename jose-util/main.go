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
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	jose "github.com/square/go-jose/v3"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("jose-util", "A command-line utility for dealing with JOSE objects")

	// Util-wide flags
	keyFile = app.Flag("key", "Path to key file (if applicable, PEM, DER or JWK format)").ExistingFile()
	inFile  = app.Flag("in", "Path to input file (if applicable, stdin if missing)").ExistingFile()
	outFile = app.Flag("out", "Path to output file (if applicable, stdout if missing)").ExistingFile()

	// Encrypt
	encryptCommand  = app.Command("encrypt", "Encrypt a plaintext, output ciphertext")
	encryptAlgFlag  = encryptCommand.Flag("alg", "Key management algorithm (e.g. RSA-OAEP)").Required().String()
	encryptEncFlag  = encryptCommand.Flag("enc", "Content encryption algorithm (e.g. A128GCM)").Required().String()
	encryptFullFlag = encryptCommand.Flag("full", "Use JSON Serialization format (instead of compact)").Bool()

	// Decrypt
	decryptCommand = app.Command("decrypt", "Decrypt a ciphertext, output plaintext")

	// Sign
	signCommand  = app.Command("sign", "Sign a payload, output signed message")
	signAlgFlag  = signCommand.Flag("alg", "Key management algorithm (e.g. RSA-OAEP)").String()
	signFullFlag = signCommand.Flag("full", "Use JSON Serialization format (instead of compact)").Bool()

	// Verify
	verifyCommand = app.Command("verify", "Verify a signed message, output payload")

	// Expand
	expandCommand    = app.Command("expand", "Expand JOSE object to JSON Serialization format")
	expandFormatFlag = expandCommand.Flag("format", "Type of message to expand (JWS or JWE, defaults to JWE)").String()

	// Base64-decode
	base64DecodeCommand = app.Command("b64decode", "Decode a base64-encoded payload (auto-selects standard/url-safe)")

	// Generate key
	generateCommand = app.Command("generate-key", "Generate a public/private key pair in JWK format")
	generateUseFlag = generateCommand.Flag("use", "Desired public key usage (use header), one of [enc sig]").Required().Enum("enc", "sig")
	generateAlgFlag = generateCommand.Flag("alg", "Desired key pair algorithm (alg header)").Required().Enum(
		// For signing
		string(jose.EdDSA),
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		string(jose.RS256), string(jose.RS384), string(jose.RS512),
		string(jose.PS256), string(jose.PS384), string(jose.PS512),
		// For encryption
		string(jose.RSA1_5), string(jose.RSA_OAEP), string(jose.RSA_OAEP_256),
		string(jose.ECDH_ES), string(jose.ECDH_ES_A128KW), string(jose.ECDH_ES_A192KW), string(jose.ECDH_ES_A256KW),
	)
	generateKeySizeFlag  = generateCommand.Flag("size", "Key size in bits (e.g. 2048 if generating an RSA key)").Int()
	generateKeyIdentFlag = generateCommand.Flag("kid", "Optional Key ID (kid header, generate random kid if not set)").String()
)

func main() {
	app.Version("v3")
	app.UsageTemplate(kingpin.LongHelpTemplate)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch command {
	case encryptCommand.FullCommand():
		encrypt()
	case decryptCommand.FullCommand():
		decrypt()
	case signCommand.FullCommand():
		sign()
	case verifyCommand.FullCommand():
		verify()
	case expandCommand.FullCommand():
		expand()
	case generateCommand.FullCommand():
		generate()
	case base64DecodeCommand.FullCommand():
		in := inputStream(*inFile)
		out := outputStream(*outFile)
		io.Copy(out, base64.NewDecoder(base64.RawStdEncoding, Base64Reader{bufio.NewReader(in)}))
		defer in.Close()
		defer out.Close()
	default:
		fmt.Fprintf(os.Stderr, "invalid command: %s\n", command)
		os.Exit(1)
	}
}
