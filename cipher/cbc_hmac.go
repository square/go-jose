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
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

const (
	nonceBytes = 16
)

func ComputeIntegrityKey(key []byte, algorithm string) []byte {
	// content integrity key size is the
	algBytes := []byte(algorithm)

	buf := []byte{0, 0, 0, 1}
	buf = append(buf, key...)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(key)*8))
	buf = append(buf, tmp...)
	buf = append(buf, algBytes...)
	buf = append(buf, []byte{0, 0, 0, 0}...)
	buf = append(buf, []byte{0, 0, 0, 0}...)
	buf = append(buf, []byte("Integrity")...)

	hashed := sha256.Sum256(buf)

	return hashed[:len(key)]
}

// NewCBCHMAC instantiates a new AEAD based on CBC+HMAC.
func NewCBCHMAC(key []byte, newBlockCipher func([]byte) (cipher.Block, error)) (cipher.AEAD, error) {
	keySize := len(key) / 2
	enc := "A128CBC+HS256"
	label := "Encryption"

	encBytes := []byte(enc)
	labelBytes := []byte(label)

	buf := []byte{0, 0, 0, 1}
	buf = append(buf, key...)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(key)*4))
	buf = append(buf, tmp...)
	buf = append(buf, encBytes...)
	buf = append(buf, []byte{0, 0, 0, 0}...)
	buf = append(buf, []byte{0, 0, 0, 0}...)
	buf = append(buf, labelBytes...)

	hashed := sha256.Sum256(buf)
	encryptionKey := hashed[:keySize]

	integrityKey := ComputeIntegrityKey(key, enc)

	blockCipher, err := newBlockCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	var hash func() hash.Hash
	switch keySize {
	case 16:
		hash = sha256.New
	case 24:
		hash = sha512.New384
	case 32:
		hash = sha512.New
	}

	return &cbcAEAD{
		hash:         hash,
		blockCipher:  blockCipher,
		authtagBytes: len(key),
		integrityKey: integrityKey,
	}, nil
}

// An AEAD based on CBC+HMAC
type cbcAEAD struct {
	hash         func() hash.Hash
	authtagBytes int
	integrityKey []byte
	blockCipher  cipher.Block
}

func (ctx *cbcAEAD) NonceSize() int {
	return nonceBytes
}

func (ctx *cbcAEAD) Overhead() int {
	// Maximum overhead is block size (for padding) plus auth tag length, where
	// the length of the auth tag is equivalent to the key size.
	return ctx.blockCipher.BlockSize() + ctx.authtagBytes
}

// Seal encrypts and authenticates the plaintext.
func (ctx *cbcAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	// Output buffer -- must take care not to mangle plaintext input.
	ciphertext := make([]byte, uint64(len(plaintext))+uint64(ctx.Overhead()))[:len(plaintext)]
	copy(ciphertext, plaintext)
	ciphertext = padBuffer(ciphertext, ctx.blockCipher.BlockSize())

	cbc := cipher.NewCBCEncrypter(ctx.blockCipher, nonce)

	cbc.CryptBlocks(ciphertext, ciphertext)
	authtag := ctx.computeAuthTag(data, nonce, ciphertext)

	ret, out := resize(dst, uint64(len(dst))+uint64(len(ciphertext))+uint64(len(authtag)))
	copy(out, ciphertext)
	copy(out[len(ciphertext):], authtag)

	return ret
}

// nonce = iv
// ciphertext = cdata
// adata = data
// kdata = doesn't exist yet
// Open decrypts and authenticates the ciphertext.
func (ctx *cbcAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(ciphertext) < ctx.authtagBytes {
		return nil, errors.New("square/go-jose: invalid ciphertext (too short)")
	}

	offset := len(ciphertext) - ctx.authtagBytes - 256 // sha256 digest size
	// fmt.Println(offset)
	// kdata:
	kdataOffset := len(ciphertext) - 256
	kdata := ciphertext[kdataOffset:]
	// fmt.Println(len(kdata))
	// fmt.Println(kdata)
	expectedTag := ctx.computeAuthTagEx(data, kdata, nonce, ciphertext[:offset])
	// fmt.Println(expectedTag)
	// fmt.Println(ciphertext[offset:kdataOffset])
	match := subtle.ConstantTimeCompare(expectedTag, ciphertext[offset:kdataOffset])
	if match != 1 {
		return nil, errors.New("square/go-jose: invalid ciphertext (auth tag mismatch)")
	}

	cbc := cipher.NewCBCDecrypter(ctx.blockCipher, nonce)

	// Make copy of ciphertext buffer, don't want to modify in place
	buffer := append([]byte{}, []byte(ciphertext[:offset])...)

	if len(buffer)%ctx.blockCipher.BlockSize() > 0 {
		return nil, errors.New("square/go-jose: invalid ciphertext (invalid length)")
	}

	cbc.CryptBlocks(buffer, buffer)

	// Remove padding
	plaintext, err := unpadBuffer(buffer, ctx.blockCipher.BlockSize())
	if err != nil {
		return nil, err
	}

	ret, out := resize(dst, uint64(len(dst))+uint64(len(plaintext)))
	copy(out, plaintext)

	return ret, nil
}

const base64PadCharacter = "="
const base64Character62 = "+"
const base64Character63 = "/"

const base64UrlCharacter62 = "-"
const base64UrlCharacter63 = "_"

var replacer = strings.NewReplacer(base64Character62, base64UrlCharacter62, base64Character63, base64UrlCharacter63)

func base64URLEncode(input []byte) string {
	// encode as base64
	encoded := base64.StdEncoding.EncodeToString(input)

	encoded = strings.Split(encoded, base64PadCharacter)[0]
	encoded = replacer.Replace(encoded)

	return encoded
}

func (ctx *cbcAEAD) computeAuthTagEx(aad, kad, iv, ciphertext []byte) []byte {
	buffer := append([]byte{}, aad...)
	buffer = append(buffer, []byte(".")...)
	blargh := []byte(base64URLEncode(kad))
	fmt.Println(blargh)
	buffer = append(buffer, blargh...)
	buffer = append(buffer, []byte(".")...)
	buffer = append(buffer, []byte(base64URLEncode(iv))...)
	buffer = append(buffer, []byte(".")...)
	buffer = append(buffer, []byte(base64URLEncode(ciphertext))...)

	fmt.Println(buffer)
	hmac := hmac.New(ctx.hash, ctx.integrityKey)
	_, _ = hmac.Write(buffer)

	return hmac.Sum(nil)[:ctx.authtagBytes]
}

// Compute an authentication tag
func (ctx *cbcAEAD) computeAuthTag(aad, nonce, ciphertext []byte) []byte {
	buffer := make([]byte, uint64(len(aad))+uint64(len(nonce))+uint64(len(ciphertext))+8)
	n := 0
	n += copy(buffer, aad)
	n += copy(buffer[n:], nonce)
	n += copy(buffer[n:], ciphertext)
	binary.BigEndian.PutUint64(buffer[n:], uint64(len(aad))*8)

	// According to documentation, Write() on hash.Hash never fails.
	hmac := hmac.New(ctx.hash, ctx.integrityKey)
	_, _ = hmac.Write(buffer)

	return hmac.Sum(nil)[:ctx.authtagBytes]
}

// resize ensures the the given slice has a capacity of at least n bytes.
// If the capacity of the slice is less than n, a new slice is allocated
// and the existing data will be copied.
func resize(in []byte, n uint64) (head, tail []byte) {
	if uint64(cap(in)) >= n {
		head = in[:n]
	} else {
		head = make([]byte, n)
		copy(head, in)
	}

	tail = head[len(in):]
	return
}

// Apply padding
func padBuffer(buffer []byte, blockSize int) []byte {
	missing := blockSize - (len(buffer) % blockSize)
	ret, out := resize(buffer, uint64(len(buffer))+uint64(missing))
	padding := bytes.Repeat([]byte{byte(missing)}, missing)
	copy(out, padding)
	return ret
}

// Remove padding
func unpadBuffer(buffer []byte, blockSize int) ([]byte, error) {
	if len(buffer)%blockSize != 0 {
		return nil, errors.New("square/go-jose: invalid padding")
	}

	last := buffer[len(buffer)-1]
	count := int(last)

	if count == 0 || count > blockSize || count > len(buffer) {
		return nil, errors.New("square/go-jose: invalid padding")
	}

	padding := bytes.Repeat([]byte{last}, count)
	if !bytes.HasSuffix(buffer, padding) {
		return nil, errors.New("square/go-jose: invalid padding")
	}

	return buffer[:len(buffer)-count], nil
}
