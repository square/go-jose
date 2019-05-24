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

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	jose "github.com/square/go-jose"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("jose-util", "A command-line utility for dealing with JOSE objects")

	// Util-wide flags
	keyFile = app.Flag("key", "Path to key file (PEM or DER-encoded)").ExistingFile()
	inFile  = app.Flag("in", "Path to input file (stdin if missing)").ExistingFile()
	outFile = app.Flag("out", "Path to output file (stdout if missing)").ExistingFile()

	// Encrypt
	encCommand  = app.Command("encrypt", "Encrypt a plaintext, output ciphertext")
	encAlgFlag  = encCommand.Flag("alg", "Key management algorithm (e.g. RSA-OAEP)").Required().String()
	encFlag     = encCommand.Flag("enc", "Content encryption algorithm (e.g. A128GCM)").Required().String()
	encFullFlag = encCommand.Flag("full", "Use full serialization format (instead of compact)").Bool()

	// Decrypt
	decryptCommand = app.Command("decrypt", "Decrypt a ciphertext, output plaintext")

	// Sign
	signCommand  = app.Command("sign", "Sign a payload, output signed message")
	signAlgFlag  = signCommand.Flag("alg", "Key management algorithm (e.g. RSA-OAEP)").Required().String()
	signFullFlag = signCommand.Flag("full", "Use full serialization format (instead of compact)").Bool()

	// Verify
	verifyCommand = app.Command("verify", "Verify a signed message, output payload")

	// Expand
	expandCommand    = app.Command("expand", "Expand JOSE object to full serialization format")
	expandFormatFlag = expandCommand.Flag("format", "Type of message to expand (JWS or JWE, defaults to JWE)").String()

	// Base64-decode
	b64DecodeCommand = app.Command("b64decode", "Decode a base64-encoded payload (auto-selects standard/url-safe)")
)

func main() {
	app.Version("v2")

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var keyBytes []byte
	var err error
	if command != "expand" {
		keyBytes, err = ioutil.ReadFile(*keyFile)
		exitOnError(err, "unable to read key file")
	}

	switch command {
	case "encrypt":
		pub, err := LoadPublicKey(keyBytes)
		exitOnError(err, "unable to read public key")

		alg := jose.KeyAlgorithm(*encAlgFlag)
		enc := jose.ContentEncryption(*encFlag)

		crypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: pub}, nil)
		exitOnError(err, "unable to instantiate encrypter")

		obj, err := crypter.Encrypt(readInput(*inFile))
		exitOnError(err, "unable to encrypt")

		var msg string
		if *encFullFlag {
			msg = obj.FullSerialize()
		} else {
			msg, err = obj.CompactSerialize()
			exitOnError(err, "unable to serialize message")
		}

		writeOutput(*outFile, []byte(msg))
	case "decrypt":
		priv, err := LoadPrivateKey(keyBytes)
		exitOnError(err, "unable to read private key")

		obj, err := jose.ParseEncrypted(string(readInput(*inFile)))
		exitOnError(err, "unable to parse message")

		plaintext, err := obj.Decrypt(priv)
		exitOnError(err, "unable to decrypt message")

		writeOutput(*outFile, plaintext)
	case "sign":
		signingKey, err := LoadPrivateKey(keyBytes)
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
	case "verify":
		verificationKey, err := LoadPublicKey(keyBytes)
		exitOnError(err, "unable to read public key")

		obj, err := jose.ParseSigned(string(readInput(*inFile)))
		exitOnError(err, "unable to parse message")

		plaintext, err := obj.Verify(verificationKey)
		exitOnError(err, "invalid signature")

		writeOutput(*outFile, plaintext)
	case "expand":
		input := string(readInput(*inFile))

		var serialized string
		var err error
		switch *expandFormatFlag {
		case "", "JWE":
			var jwe *jose.JSONWebEncryption
			jwe, err = jose.ParseEncrypted(input)
			if err == nil {
				serialized = jwe.FullSerialize()
			}
		case "JWS":
			var jws *jose.JSONWebSignature
			jws, err = jose.ParseSigned(input)
			if err == nil {
				serialized = jws.FullSerialize()
			}
		}

		exitOnError(err, "unable to expand message")
		writeOutput(*outFile, []byte(serialized))
		writeOutput(*outFile, []byte("\n"))
	case "b64decode":
		in := bufio.NewReader(inputStream(*inFile))
		io.Copy(outputStream(*outFile), base64.NewDecoder(base64.RawStdEncoding, in))
	default:
		fmt.Fprintf(os.Stderr, "invalid command: %s\n", command)
		os.Exit(1)
	}
}

// Exit and print error message if we encountered a problem
func exitOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// Read input from file or stdin
func readInput(path string) []byte {
	var bytes []byte
	var err error

	if path != "" {
		bytes, err = ioutil.ReadFile(path)
	} else {
		bytes, err = ioutil.ReadAll(os.Stdin)
	}

	exitOnError(err, "unable to read input")
	return bytes
}

// Get input stream from file or stdin
func inputStream(path string) *os.File {
	var file *os.File
	var err error

	if path != "" {
		file, err = os.Open(path)
	} else {
		file = os.Stdin
	}

	exitOnError(err, "unable to read input")
	return file
}

// Write output to file or stdin
func writeOutput(path string, data []byte) {
	var err error

	if path != "" {
		err = ioutil.WriteFile(path, data, 0644)
	} else {
		_, err = os.Stdout.Write(data)
	}

	exitOnError(err, "unable to write output")
}

// Get output stream for file or stdout
func outputStream(path string) *os.File {
	var file *os.File
	var err error

	if path != "" {
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	} else {
		file = os.Stdout
	}

	exitOnError(err, "unable to write output")
	return file
}
