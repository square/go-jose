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
	"io"
	"io/ioutil"
	"os"
)

// Read input from file or stdin
func readInput(path string) []byte {
	var bytes []byte
	var err error

	if path != "" {
		bytes, err = ioutil.ReadFile(path)
	} else {
		bytes, err = ioutil.ReadAll(os.Stdin)
	}

	app.FatalIfError(err, "unable to read input")
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

	app.FatalIfError(err, "unable to read input")
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

	app.FatalIfError(err, "unable to write output")
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

	app.FatalIfError(err, "unable to write output")
	return file
}

// Byte contents of key file
func keyBytes() []byte {
	keyBytes, err := ioutil.ReadFile(*keyFile)
	app.FatalIfError(err, "unable to read key file")
	return keyBytes
}

// Write new file to current dir
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
