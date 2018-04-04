/*-
 * Copyright 2018 Square Inc.
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
	"crypto"
	"fmt"
	"testing"
)

type signWrapper struct {
	pk      crypto.PublicKey
	wrapped payloadSigner
	algs    []SignatureAlgorithm
}

var _ = OpaqueSigner(&signWrapper{})

func (sw *signWrapper) Algs() []SignatureAlgorithm {
	return sw.algs
}

func (sw *signWrapper) Public() *JSONWebKey {
	return &JSONWebKey{Key: sw.pk}
}

func (sw *signWrapper) SignPayload(payload []byte, alg SignatureAlgorithm) ([]byte, error) {
	sig, err := sw.wrapped.signPayload(payload, alg)
	if err != nil {
		return nil, err
	}
	return sig.Signature, nil
}

type verifyWrapper struct {
	wrapped payloadVerifier
}

var _ = OpaqueVerifier(&verifyWrapper{})

func (vw *verifyWrapper) VerifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	return vw.wrapped.verifyPayload(payload, signature, alg)
}

func TestRoundtripsJWSOpaque(t *testing.T) {
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			sw, vw := makeOpaqueSignerVerifier(t, signingKey, verificationKey, alg)

			err := RoundtripJWS(alg, serializer, corrupter, sw, verificationKey, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, signingKey, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, sw, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}
		}
	}
}

func makeOpaqueSignerVerifier(t *testing.T, signingKey, verificationKey interface{}, alg SignatureAlgorithm) (OpaqueSigner, OpaqueVerifier) {
	ri, err := makeJWSRecipient(alg, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newVerifier(verificationKey)
	if err != nil {
		t.Fatal(err)
	}
	return &signWrapper{wrapped: ri.signer, algs: []SignatureAlgorithm{alg}}, &verifyWrapper{wrapped: verifier}
}
