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

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("jose-util", "A command-line utility for dealing with JOSE objects")

	// Util-wide flags
	keyFile = app.Flag("key", "Path to key file (PEM or DER-encoded)").ExistingFile()
	inFile  = app.Flag("in", "Path to input file (stdin if missing)").ExistingFile()
	outFile = app.Flag("out", "Path to output file (stdout if missing)").ExistingFile()

	// Encrypt
	encryptCommand  = app.Command("encrypt", "Encrypt a plaintext, output ciphertext")
	encryptAlgFlag  = encryptCommand.Flag("alg", "Key management algorithm (e.g. RSA-OAEP)").Required().String()
	encryptEncFlag  = encryptCommand.Flag("enc", "Content encryption algorithm (e.g. A128GCM)").Required().String()
	encryptFullFlag = encryptCommand.Flag("full", "Use full serialization format (instead of compact)").Bool()

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
	base64DecodeCommand = app.Command("b64decode", "Decode a base64-encoded payload (auto-selects standard/url-safe)")
)

func main() {
	app.Version("v3")
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

// Exit and print error message if we encountered a problem
func exitOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}
