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

func expand() {
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

	app.FatalIfError(err, "unable to expand message")
	writeOutput(*outFile, []byte(serialized))
	writeOutput(*outFile, []byte("\n"))
}
