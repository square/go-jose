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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

// We generate only a single RSA and EC key for testing, speeds up tests.
var rsaTestKey, _ = rsa.GenerateKey(rand.Reader, 2048)

var ecTestKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var ecTestKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
var ecTestKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

func RoundtripJWE(keyAlg KeyAlgorithm, encAlg ContentEncryption, compressionAlg CompressionAlgorithm, serializer func(*JweObject) (string, error), corrupter func(*JweObject), aad []byte, encryptionKey interface{}, decryptionKey interface{}) error {
	enc, err := NewEncrypter(keyAlg, encAlg, encryptionKey)
	if err != nil {
		return fmt.Errorf("error on new encrypter: %s", err)
	}

	enc.SetCompression(compressionAlg)

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := enc.EncryptWithAuthData(input, aad)
	if err != nil {
		return fmt.Errorf("error in encrypt: %s", err)
	}

	msg, err := serializer(obj)
	if err != nil {
		return fmt.Errorf("error in serializer: %s", err)
	}

	parsed, err := ParseEncrypted(msg)
	if err != nil {
		return fmt.Errorf("error in parse: %s", err)
	}

	// (Maybe) mangle object
	corrupter(parsed)

	if bytes.Compare(parsed.GetAuthData(), aad) != 0 {
		return fmt.Errorf("auth data in parsed object does not match")
	}

	dec, err := NewDecrypter(decryptionKey)
	if err != nil {
		return fmt.Errorf("error on new decrypter: %s", err)
	}

	output, err := dec.Decrypt(parsed)
	if err != nil {
		return fmt.Errorf("error on decrypt: %s", err)
	}

	if bytes.Compare(input, output) != 0 {
		return fmt.Errorf("Decrypted output does not match input, got '%s' but wanted '%s'", output, input)
	}

	return nil
}

func TestRoundtripsJWE(t *testing.T) {
	// Test matrix
	keyAlgs := []KeyAlgorithm{
		DIRECT, ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, A128KW, A192KW, A256KW,
		RSA1_5, RSA_OAEP, RSA_OAEP_256, A128GCMKW, A192GCMKW, A256GCMKW}
	encAlgs := []ContentEncryption{A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512}
	zipAlgs := []CompressionAlgorithm{NONE, DEFLATE}

	serializers := []func(*JweObject) (string, error){
		func(obj *JweObject) (string, error) { return obj.CompactSerialize() },
		func(obj *JweObject) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JweObject) {}

	// Note: can't use AAD with compact serialization
	aads := [][]byte{
		nil,
		[]byte("Ut enim ad minim veniam"),
	}

	// Test all different configurations
	for _, alg := range keyAlgs {
		for _, enc := range encAlgs {
			for _, key := range generateTestKeys(alg, enc) {
				for _, zip := range zipAlgs {
					for i, serializer := range serializers {
						err := RoundtripJWE(alg, enc, zip, serializer, corrupter, aads[i], key.enc, key.dec)
						if err != nil {
							t.Error(err, alg, enc, zip, i)
						}
					}
				}
			}
		}
	}
}

func TestRoundtripsJWECorrupted(t *testing.T) {
	// Test matrix
	keyAlgs := []KeyAlgorithm{DIRECT, ECDH_ES, ECDH_ES_A128KW, A128KW, RSA1_5, RSA_OAEP, RSA_OAEP_256, A128GCMKW}
	encAlgs := []ContentEncryption{A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512}
	zipAlgs := []CompressionAlgorithm{NONE, DEFLATE}

	serializers := []func(*JweObject) (string, error){
		func(obj *JweObject) (string, error) { return obj.CompactSerialize() },
		func(obj *JweObject) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupters := []func(*JweObject){
		func(obj *JweObject) {
			// Set invalid AAD
			obj.aad = []byte("###")
		},
		func(obj *JweObject) {
			// Set invalid ciphertext
			obj.ciphertext = []byte("###")
		},
		func(obj *JweObject) {
			// Set invalid auth tag
			obj.tag = []byte("###")
		},
	}

	// Note: can't use AAD with compact serialization
	aads := [][]byte{
		nil,
		[]byte("Ut enim ad minim veniam"),
	}

	// Test all different configurations
	for _, alg := range keyAlgs {
		for _, enc := range encAlgs {
			for _, key := range generateTestKeys(alg, enc) {
				for _, zip := range zipAlgs {
					for i, serializer := range serializers {
						for j, corrupter := range corrupters {
							err := RoundtripJWE(alg, enc, zip, serializer, corrupter, aads[i], key.enc, key.dec)
							if err == nil {
								t.Error("failed to detect corrupt data", err, alg, enc, zip, i, j)
							}
						}
					}
				}
			}
		}
	}
}

func TestNewEncrypterErrors(t *testing.T) {
	_, err := NewEncrypter("XYZ", "XYZ", nil)
	if err == nil {
		t.Error("was able to instantiate encrypter with invalid cipher")
	}

	_, err = NewMultiEncrypter("XYZ")
	if err == nil {
		t.Error("was able to instantiate multi-encrypter with invalid cipher")
	}

	_, err = NewEncrypter(DIRECT, A128GCM, nil)
	if err == nil {
		t.Error("was able to instantiate encrypter with invalid direct key")
	}

	_, err = NewEncrypter(ECDH_ES, A128GCM, nil)
	if err == nil {
		t.Error("was able to instantiate encrypter with invalid EC key")
	}
}

func TestMultiRecipientJWE(t *testing.T) {
	enc, err := NewMultiEncrypter(A128GCM)
	if err != nil {
		panic(err)
	}

	err = enc.AddRecipient(RSA_OAEP, &rsaTestKey.PublicKey)
	if err != nil {
		t.Error("error when adding RSA recipient: %s", err)
	}

	sharedKey := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	}

	err = enc.AddRecipient(A256GCMKW, sharedKey)
	if err != nil {
		t.Error("error when adding AES recipient: ", err)
		return
	}

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := enc.Encrypt(input)
	if err != nil {
		t.Error("error in encrypt: ", err)
		return
	}

	msg := obj.FullSerialize()

	parsed, err := ParseEncrypted(msg)
	if err != nil {
		t.Error("error in parse: ", err)
		return
	}

	dec, err := NewDecrypter(rsaTestKey)
	if err != nil {
		t.Error("error on new decrypter with RSA: ", err)
		return
	}

	output, err := dec.Decrypt(parsed)
	if err != nil {
		t.Error("error on decrypt with RSA: ", err)
		return
	}

	if bytes.Compare(input, output) != 0 {
		t.Error("Decrypted output does not match input: ", output, input)
		return
	}

	dec, err = NewDecrypter(sharedKey)
	if err != nil {
		t.Error("error on new decrypter with AES: ", err)
		return
	}

	output, err = dec.Decrypt(parsed)
	if err != nil {
		t.Error("error on decrypt with AES: ", err)
		return
	}

	if bytes.Compare(input, output) != 0 {
		t.Error("Decrypted output does not match input", output, input)
		return
	}
}

func TestMultiRecipientErrors(t *testing.T) {
	enc, err := NewMultiEncrypter(A128GCM)
	if err != nil {
		panic(err)
	}

	input := []byte("Lorem ipsum dolor sit amet")
	_, err = enc.Encrypt(input)
	if err == nil {
		t.Error("should fail when encrypting to zero recipients")
	}

	err = enc.AddRecipient(DIRECT, nil)
	if err == nil {
		t.Error("should reject DIRECT mode when encrypting to multiple recipients")
	}

	err = enc.AddRecipient(ECDH_ES, nil)
	if err == nil {
		t.Error("should reject ECDH_ES mode when encrypting to multiple recipients")
	}

	err = enc.AddRecipient(RSA1_5, nil)
	if err == nil {
		t.Error("should reject invalid recipient key")
	}
}

type testKey struct {
	enc, dec interface{}
}

func symmetricTestKey(size int) []testKey {
	key, _, _ := randomKeyGenerator{size: size}.genKey()

	return []testKey{
		testKey{
			enc: key,
			dec: key,
		},
	}
}

func generateTestKeys(keyAlg KeyAlgorithm, encAlg ContentEncryption) []testKey {
	switch keyAlg {
	case DIRECT:
		return symmetricTestKey(getContentCipher(encAlg).keySize())
	case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
		return []testKey{
			testKey{
				dec: ecTestKey256,
				enc: &ecTestKey256.PublicKey,
			},
			testKey{
				dec: ecTestKey384,
				enc: &ecTestKey384.PublicKey,
			},
			testKey{
				dec: ecTestKey521,
				enc: &ecTestKey521.PublicKey,
			},
		}
	case A128GCMKW, A128KW:
		return symmetricTestKey(16)
	case A192GCMKW, A192KW:
		return symmetricTestKey(24)
	case A256GCMKW, A256KW:
		return symmetricTestKey(32)
	case RSA1_5, RSA_OAEP, RSA_OAEP_256:
		return []testKey{testKey{
			dec: rsaTestKey,
			enc: &rsaTestKey.PublicKey,
		}}
	}

	panic("Must update test case")
}

func RunRoundtripsJWE(b *testing.B, alg KeyAlgorithm, enc ContentEncryption, zip CompressionAlgorithm, priv, pub interface{}) {
	serializer := func(obj *JweObject) (string, error) {
		return obj.CompactSerialize()
	}

	corrupter := func(obj *JweObject) {}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := RoundtripJWE(alg, enc, zip, serializer, corrupter, nil, pub, priv)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkRoundtripsWithOAEPAndGCM(b *testing.B) {
	RunRoundtripsJWE(b, RSA_OAEP, A128GCM, NONE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithPKCSAndGCM(b *testing.B) {
	RunRoundtripsJWE(b, RSA1_5, A128GCM, NONE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithOAEPAndCBC(b *testing.B) {
	RunRoundtripsJWE(b, RSA_OAEP, A128CBC_HS256, NONE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithPKCSAndCBC(b *testing.B) {
	RunRoundtripsJWE(b, RSA1_5, A128CBC_HS256, NONE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithDirectGCM128(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 16}.genKey()
	RunRoundtripsJWE(b, DIRECT, A128GCM, NONE, cek, cek)
}

func BenchmarkRoundtripsWithDirectCBC128(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 32}.genKey()
	RunRoundtripsJWE(b, DIRECT, A128CBC_HS256, NONE, cek, cek)
}

func BenchmarkRoundtripsWithDirectGCM256(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 32}.genKey()
	RunRoundtripsJWE(b, DIRECT, A256GCM, NONE, cek, cek)
}

func BenchmarkRoundtripsWithDirectCBC256(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 64}.genKey()
	RunRoundtripsJWE(b, DIRECT, A256CBC_HS512, NONE, cek, cek)
}

func BenchmarkRoundtripsWithOAEPAndGCM128AndDEFLATE(b *testing.B) {
	RunRoundtripsJWE(b, RSA_OAEP, A128GCM, DEFLATE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithPKCSAndGCM128AndDEFLATE(b *testing.B) {
	RunRoundtripsJWE(b, RSA1_5, A128GCM, DEFLATE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithOAEPAndCBC128AndDEFLATE(b *testing.B) {
	RunRoundtripsJWE(b, RSA_OAEP, A128CBC_HS256, DEFLATE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithPKCSAndCBC128AndDEFLATE(b *testing.B) {
	RunRoundtripsJWE(b, RSA1_5, A128CBC_HS256, DEFLATE, rsaTestKey, &rsaTestKey.PublicKey)
}

func BenchmarkRoundtripsWithDirectGCM128AndDEFLATE(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 16}.genKey()
	RunRoundtripsJWE(b, DIRECT, A128GCM, DEFLATE, cek, cek)
}

func BenchmarkRoundtripsWithDirectCBC128AndDEFLATE(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 32}.genKey()
	RunRoundtripsJWE(b, DIRECT, A128CBC_HS256, DEFLATE, cek, cek)
}

func BenchmarkRoundtripsWithAESKWAndGCM128(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 16}.genKey()
	RunRoundtripsJWE(b, A128KW, A128GCM, NONE, cek, cek)
}

func BenchmarkRoundtripsWithAESKWAndCBC256(b *testing.B) {
	cek, _, _ := randomKeyGenerator{size: 32}.genKey()
	RunRoundtripsJWE(b, A256KW, A256GCM, NONE, cek, cek)
}

func BenchmarkRoundtripsWithECDHOnP256AndGCM128(b *testing.B) {
	RunRoundtripsJWE(b, ECDH_ES, A128GCM, DEFLATE, ecTestKey256, &ecTestKey256.PublicKey)
}

func BenchmarkRoundtripsWithECDHOnP384AndGCM128(b *testing.B) {
	RunRoundtripsJWE(b, ECDH_ES, A128GCM, DEFLATE, ecTestKey384, &ecTestKey384.PublicKey)
}

func BenchmarkRoundtripsWithECDHOnP521AndGCM128(b *testing.B) {
	RunRoundtripsJWE(b, ECDH_ES, A128GCM, DEFLATE, ecTestKey521, &ecTestKey521.PublicKey)
}
