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

package josecipher

import (
	"crypto"
	"encoding/binary"
	"hash"
	"io"
)

type concatKDF struct {
	z, info []byte
	i       uint32
	size    int
	cache   []byte
	hasher  hash.Hash
}

// NewConcatKDF builds a KDF reader based on the given inputs.
func NewConcatKDF(hash crypto.Hash, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) io.Reader {
	info := []byte{}
	info = append(info, algID...)
	info = append(info, ptyUInfo...)
	info = append(info, ptyVInfo...)
	info = append(info, supPubInfo...)
	info = append(info, supPrivInfo...)

	outSize := len(hash.New().Sum(nil))

	return &concatKDF{
		z:      z,
		info:   info,
		hasher: hash.New(),
		size:   outSize,
		cache:  []byte{},
		i:      1,
	}
}

func (ctx *concatKDF) Read(out []byte) (int, error) {
	copied := copy(out, ctx.cache)
	ctx.cache = ctx.cache[copied:]

	for copied < len(out) {
		ctx.hasher.Reset()

		// Write on a hash.Hash never fails
		_ = binary.Write(ctx.hasher, binary.BigEndian, ctx.i)
		_, _ = ctx.hasher.Write(ctx.z)
		_, _ = ctx.hasher.Write(ctx.info)

		hash := ctx.hasher.Sum(nil)
		chunkCopied := copy(out[copied:], hash)
		copied += chunkCopied
		ctx.cache = hash[chunkCopied:]

		ctx.i++
	}

	return copied, nil
}
