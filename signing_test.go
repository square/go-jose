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
	"fmt"
	"testing"
)

func RoundtripJWS(sigAlg SignatureAlgorithm, serializer func(*JwsObject) (string, error), corrupter func(*JwsObject), signingKey interface{}, verificationKey interface{}) error {
	signer, err := NewSigner(sigAlg, signingKey)
	if err != nil {
		return fmt.Errorf("error on new signer: %s", err)
	}

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := signer.Sign(input)
	if err != nil {
		return fmt.Errorf("error on sign: %s", err)
	}

	msg, err := serializer(obj)
	if err != nil {
		return fmt.Errorf("error on serialize: %s", err)
	}

	obj, err = ParseSigned(msg)
	if err != nil {
		return fmt.Errorf("error on parse: %s", err)
	}

	// (Maybe) mangle the object
	corrupter(obj)

	verifier, err := NewVerifier(verificationKey)
	if err != nil {
		return fmt.Errorf("error on new verifier: %s", err)
	}

	output, err := verifier.Verify(obj)
	if err != nil {
		return fmt.Errorf("error on verify: %s", err)
	}

	if bytes.Compare(output, input) != 0 {
		return fmt.Errorf("input/output do not match, got '%s', expected '%s'", output, input)
	}

	return nil
}

func TestRoundtripsJWS(t *testing.T) {
	// Test matrix
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, HS256, HS384, HS512, ES256, ES384, ES512}

	serializers := []func(*JwsObject) (string, error){
		func(obj *JwsObject) (string, error) { return obj.CompactSerialize() },
		func(obj *JwsObject) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JwsObject) {}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			err := RoundtripJWS(alg, serializer, corrupter, signingKey, verificationKey)
			if err != nil {
				t.Error(err, alg, i)
			}
		}
	}
}

func TestRoundtripsJWSCorruptSignature(t *testing.T) {
	// Test matrix
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, HS256, HS384, HS512, ES256, ES384, ES512}

	serializers := []func(*JwsObject) (string, error){
		func(obj *JwsObject) (string, error) { return obj.CompactSerialize() },
		func(obj *JwsObject) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupters := []func(*JwsObject){
		func(obj *JwsObject) {
			// Changes bytes in signature
			obj.signatures[0].signature[10]++
		},
		func(obj *JwsObject) {
			// Set totally invalid signature
			obj.signatures[0].signature = []byte("###")
		},
	}

	// Test all different configurations
	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			for j, corrupter := range corrupters {
				err := RoundtripJWS(alg, serializer, corrupter, signingKey, verificationKey)
				if err == nil {
					t.Error("failed to detect corrupt signature", err, alg, i, j)
				}
			}
		}
	}
}

func TestMultiRecipientJWS(t *testing.T) {
	signer := NewMultiSigner()

	sharedKey := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	}

	signer.AddRecipient(RS256, rsaTestKey)
	signer.AddRecipient(HS384, sharedKey)

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := signer.Sign(input)
	if err != nil {
		t.Error("error on sign: ", err)
		return
	}

	_, err = obj.CompactSerialize()
	if err == nil {
		t.Error("message with multiple recipient was compact serialized")
	}

	msg := obj.FullSerialize()

	obj, err = ParseSigned(msg)
	if err != nil {
		t.Error("error on parse: ", err)
		return
	}

	verifierRSA, err := NewVerifier(&rsaTestKey.PublicKey)
	if err != nil {
		t.Error("error on new verifier: ", err)
		return
	}

	verifierHMAC, err := NewVerifier(sharedKey)
	if err != nil {
		t.Error("error on new verifier: ", err)
		return
	}

	output, err := verifierRSA.Verify(obj)
	if err != nil {
		t.Error("error on verify: ", err)
		return
	}

	output, err = verifierHMAC.Verify(obj)
	if err != nil {
		t.Error("error on verify: ", err)
		return
	}

	if bytes.Compare(output, input) != 0 {
		t.Error("input/output do not match", output, input)
		return
	}
}

func GenerateSigningTestKey(sigAlg SignatureAlgorithm) (sig, ver interface{}) {
	switch sigAlg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		sig = rsaTestKey
		ver = &rsaTestKey.PublicKey
	case HS256, HS384, HS512:
		sig, _, _ = randomKeyGenerator{size: 16}.genKey()
		ver = sig
	case ES256:
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES384:
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES512:
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	default:
		panic("Must update test case")
	}

	return
}

func TestInvalidSignerAlg(t *testing.T) {
	_, err := NewSigner("XYZ", nil)
	if err == nil {
		t.Error("should not accept invalid algorithm")
	}

	_, err = NewSigner("XYZ", []byte{})
	if err == nil {
		t.Error("should not accept invalid algorithm")
	}

	_, err = NewVerifier(nil)
	if err == nil {
		t.Error("should not accept invalid algorithm")
	}
}

type allowAllVerifier struct{}

// Dummy verifier that allows everything
func (ctx allowAllVerifier) verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	return nil
}

func TestInvalidJWS(t *testing.T) {
	signer, err := NewSigner(PS256, rsaTestKey)
	if err != nil {
		panic(err)
	}

	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	obj.signatures[0].header = map[string]interface{}{
		"crit": []string{"TEST"},
	}

	ver, err := NewVerifier(&rsaTestKey.PublicKey)
	if err != nil {
		panic(err)
	}

	verifier := ver.(*genericVerifier)

	// Mock out verifier
	verifier.verifier = allowAllVerifier{}

	_, err = verifier.Verify(obj)
	if err == nil {
		t.Error("should not verify message with unknown crit header")
	}

	// Try without alg header
	obj.signatures[0].protected = map[string]interface{}{}
	obj.signatures[0].header = map[string]interface{}{}

	_, err = verifier.Verify(obj)
	if err == nil {
		t.Error("should not verify message with missing headers")
	}

	// Set an invalid header
	obj.signatures[0].protected = map[string]interface{}{
		"alg": []string{"X", "Y", "Z"},
	}

	_, err = verifier.Verify(obj)
	if err == nil {
		t.Error("should not verify message with invalid headers")
	}
}
