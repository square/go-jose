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

package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"reflect"
)

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter interface {
	Encrypt(plaintext []byte) (*JsonWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JsonWebEncryption, error)
	SetCompression(alg CompressionAlgorithm)
	SetKid(kid string)
}

// MultiEncrypter represents an encrypter which supports multiple recipients.
type MultiEncrypter interface {
	Encrypt(plaintext []byte) (*JsonWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JsonWebEncryption, error)
	SetCompression(alg CompressionAlgorithm)
	AddRecipient(alg KeyAlgorithm, encryptionKey interface{}) error
}

// A generic content cipher
type contentCipher interface {
	keySize() int
	encrypt(cek []byte, aad, plaintext []byte) (*aeadParts, error)
	decrypt(cek []byte, aad []byte, parts *aeadParts) ([]byte, error)
}

// A key generator (for generating/getting a CEK)
type keyGenerator interface {
	keySize() int
	genKey() ([]byte, rawHeader, error)
}

// A generic key encrypter
type keyEncrypter interface {
	encryptKey(cek []byte, alg KeyAlgorithm) (recipientInfo, error) // Encrypt a key
}

// A generic key decrypter
type keyDecrypter interface {
	decryptKey(headers rawHeader, recipient *recipientInfo, generator keyGenerator) ([]byte, error) // Decrypt a key
}

// A generic encrypter based on the given key encrypter and content cipher.
type genericEncrypter struct {
	contentAlg     ContentEncryption
	compressionAlg CompressionAlgorithm
	cipher         contentCipher
	recipients     []recipientKeyInfo
	keyGenerator   keyGenerator
	kid            string
}

type recipientKeyInfo struct {
	keyAlg       KeyAlgorithm
	keyEncrypter keyEncrypter
}

// SetCompression sets a compression algorithm to be applied before encryption.
func (ctx *genericEncrypter) SetCompression(compressionAlg CompressionAlgorithm) {
	ctx.compressionAlg = compressionAlg
}

// SetUnprotectedHeader sets a JWE unprotected header
func (ctx *genericEncrypter) SetKid(kid string) {
	ctx.kid = kid
}

// NewEncrypter creates an appropriate encrypter based on the key type
func NewEncrypter(alg KeyAlgorithm, enc ContentEncryption, encryptionKey interface{}) (Encrypter, error) {
	encrypter := &genericEncrypter{
		contentAlg:     enc,
		compressionAlg: NONE,
		recipients:     []recipientKeyInfo{},
		cipher:         getContentCipher(enc),
	}

	if encrypter.cipher == nil {
		return nil, ErrUnsupportedAlgorithm
	}

	switch alg {
	case DIRECT:
		// Direct encryption mode must be treated differently
		if reflect.TypeOf(encryptionKey) != reflect.TypeOf([]byte{}) {
			return nil, ErrUnsupportedKeyType
		}
		encrypter.keyGenerator = staticKeyGenerator{
			key: encryptionKey.([]byte),
		}
		recipient, _ := newSymmetricRecipient(alg, encryptionKey.([]byte))
		encrypter.recipients = []recipientKeyInfo{recipient}
		return encrypter, nil
	case ECDH_ES:
		// ECDH-ES (w/o key wrapping) is similar to DIRECT mode
		typeOf := reflect.TypeOf(encryptionKey)
		if typeOf != reflect.TypeOf(&ecdsa.PublicKey{}) {
			return nil, ErrUnsupportedKeyType
		}
		encrypter.keyGenerator = ecKeyGenerator{
			size:      encrypter.cipher.keySize(),
			algID:     string(enc),
			publicKey: encryptionKey.(*ecdsa.PublicKey),
		}
		recipient, _ := newECDHRecipient(alg, encryptionKey.(*ecdsa.PublicKey))
		encrypter.recipients = []recipientKeyInfo{recipient}
		return encrypter, nil
	default:
		// Can just add a standard recipient
		encrypter.keyGenerator = randomKeyGenerator{
			size: encrypter.cipher.keySize(),
		}
		err := encrypter.AddRecipient(alg, encryptionKey)
		return encrypter, err
	}
}

// NewMultiEncrypter creates a multi-encrypter based on the given parameters
func NewMultiEncrypter(enc ContentEncryption) (MultiEncrypter, error) {
	cipher := getContentCipher(enc)

	if cipher == nil {
		return nil, ErrUnsupportedAlgorithm
	}

	encrypter := &genericEncrypter{
		contentAlg:     enc,
		compressionAlg: NONE,
		recipients:     []recipientKeyInfo{},
		cipher:         cipher,
		keyGenerator: randomKeyGenerator{
			size: cipher.keySize(),
		},
	}

	return encrypter, nil
}

func (ctx *genericEncrypter) AddRecipient(alg KeyAlgorithm, encryptionKey interface{}) (err error) {
	var recipient recipientKeyInfo

	switch alg {
	case DIRECT, ECDH_ES:
		return fmt.Errorf("square/go-jose: key algorithm '%s' not supported in multi-recipient mode", alg)
	}

	switch encryptionKey := encryptionKey.(type) {
	case *rsa.PublicKey:
		recipient, err = newRSARecipient(alg, encryptionKey)
	case []byte:
		recipient, err = newSymmetricRecipient(alg, encryptionKey)
	case *ecdsa.PublicKey:
		recipient, err = newECDHRecipient(alg, encryptionKey)
	default:
		return ErrUnsupportedKeyType
	}

	if err == nil {
		ctx.recipients = append(ctx.recipients, recipient)
	}
	return err
}

// newDecrypter creates an appropriate decrypter based on the key type
func newDecrypter(decryptionKey interface{}) (keyDecrypter, error) {
	switch decryptionKey := decryptionKey.(type) {
	case *rsa.PrivateKey:
		return &rsaDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case *ecdsa.PrivateKey:
		return &ecDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case []byte:
		return &symmetricKeyCipher{
			key: decryptionKey,
		}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// Implementation of encrypt method producing a JWE object.
func (ctx *genericEncrypter) Encrypt(plaintext []byte) (*JsonWebEncryption, error) {
	return ctx.EncryptWithAuthData(plaintext, nil)
}

// Implementation of encrypt method producing a JWE object.
func (ctx *genericEncrypter) EncryptWithAuthData(plaintext, aad []byte) (*JsonWebEncryption, error) {
	obj := &JsonWebEncryption{}
	obj.aad = aad

	obj.protected = &rawHeader{
		Enc: ctx.contentAlg,
	}
	obj.recipients = make([]recipientInfo, len(ctx.recipients))

	if len(ctx.recipients) == 0 {
		return nil, fmt.Errorf("square/go-jose: no recipients to encrypt to")
	}

	cek, headers, err := ctx.keyGenerator.genKey()
	if err != nil {
		return nil, err
	}

	obj.protected.merge(&headers)

	for i, info := range ctx.recipients {
		recipient, err := info.keyEncrypter.encryptKey(cek, info.keyAlg)
		if err != nil {
			return nil, err
		}

		recipient.header.Alg = string(info.keyAlg)
		obj.recipients[i] = recipient
	}

	if len(ctx.recipients) == 1 {
		// Move per-recipient headers into main protected header if there's
		// only a single recipient.
		obj.protected.merge(obj.recipients[0].header)
		obj.recipients[0].header = nil
	}

	if ctx.compressionAlg != NONE {
		plaintext, err = compress(ctx.compressionAlg, plaintext)
		if err != nil {
			return nil, err
		}

		obj.protected.Zip = ctx.compressionAlg
	}

	if ctx.kid != "" {
		obj.protected.Kid = ctx.kid
	}

	authData := obj.computeAuthData()
	parts, err := ctx.cipher.encrypt(cek, authData, plaintext)
	if err != nil {
		return nil, err
	}

	obj.iv = parts.iv
	obj.ciphertext = parts.ciphertext
	obj.tag = parts.tag

	return obj, nil
}

// Decrypt and validate the object and return the plaintext.
func (obj JsonWebEncryption) Decrypt(decryptionKey interface{}) ([]byte, error) {
	headers := obj.mergedHeaders(nil)

	if len(headers.Crit) > 0 {
		return nil, fmt.Errorf("square/go-jose: unsupported crit header")
	}

	decrypter, err := newDecrypter(decryptionKey)
	if err != nil {
		return nil, err
	}

	cipher := getContentCipher(headers.Enc)
	if cipher == nil {
		return nil, fmt.Errorf("square/go-jose: unsupported enc value '%s'", string(headers.Enc))
	}

	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}

	authData := obj.computeAuthData()

	var plaintext []byte
	for _, recipient := range obj.recipients {
		recipientHeaders := obj.mergedHeaders(&recipient)

		cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
		if err == nil {
			// Found a valid CEK -- let's try to decrypt.
			plaintext, err = cipher.decrypt(cek, authData, parts)
			if err == nil {
				break
			}
		}
	}

	if plaintext == nil {
		return nil, ErrCryptoFailure
	}

	// The "zip" header paramter may only be present in the protected header.
	if obj.protected.Zip != "" {
		plaintext, err = decompress(obj.protected.Zip, plaintext)
	}

	return plaintext, err
}
