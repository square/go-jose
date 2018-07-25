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

// When implemented, allows key types and signing algorithms that are not natively supported by Golang or go-jose to be
// used for signing operations.
//
// Examples of such keys include those implemented by PKCS11 providers, native keys where a non native entropy source
// must be used to generate signatures, etc.
//
// In the case where the signing requires specific option values (e.g. PSS Salt Length, etc.) it is the responsibility
// of the implementer to handle these properly in the constructor of the concrete implementation of AbstractKey and in
// its implementation of the SignPayload function.
type AbstractSigner interface {
	// The Key Identifier of the key to be inserted into the `kid` claim of the jose header.
	KeyID() string

	// Signs the payload of the message.
	SignPayload(payload []byte, algorithm SignatureAlgorithm) (signature []byte, err error)
}

// Used in signing.go to provide implement the functions of the payloadSigner interface
type abstractSigner struct {
	signer AbstractSigner
}

func newAbstractSigner(signer AbstractSigner, algorithm SignatureAlgorithm) (rsi recipientSigInfo, err error) {
	return recipientSigInfo{
		sigAlg: algorithm,
		keyID:  signer.KeyID(),
		signer: &abstractSigner{signer: signer},
	}, nil
}

func (ctx *abstractSigner) signPayload(payload []byte, algorithm SignatureAlgorithm) (sig Signature, err error) {
	sig = Signature{}
	if sig.Signature, err = ctx.signer.SignPayload(payload, algorithm); err == nil {
		sig.protected = &rawHeader{}
	}
	return
}

// When implemented, allows key types and verification algorithms that are not natively supported by Golang or go-jose
// to be used for signature verification operatins operations.
// Examples of such keys include those implemented by PKCS11 providers, native keys where a non native entropy source
// must be used to generate signatures, etc.
//
// In the case where the verifivation requires specific option values it is the responsibility of the implementer to
// handle these properly in the constructor of the concrete implementation of AbstractKey and in its implementation of
// the Verify function.
type AbstractVerifier interface {
	Verify(payload []byte, signature []byte, algorithm SignatureAlgorithm) error
}

// Used in signing.go to provide implement the functions of the payloadVerifier interface
type abstractVerifier struct {
	abstractVerifier AbstractVerifier
}

func newAbstractVerifier(verifier AbstractVerifier) (payloadVerifier, error) {
	return &abstractVerifier{verifier}, nil
}

func (ctx *abstractVerifier) verifyPayload(payload []byte, signature []byte, algorithm SignatureAlgorithm) error {
	return ctx.abstractVerifier.Verify(payload, signature, algorithm)
}
