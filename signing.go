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
)

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer interface {
	Sign(payload []byte) (*JsonWebSignature, error)
}

// MultiSigner represents a signer which supports multiple recipients.
type MultiSigner interface {
	Sign(payload []byte) (*JsonWebSignature, error)
	AddRecipient(alg SignatureAlgorithm, signingKey interface{}) error
}

type payloadSigner interface {
	signPayload(payload []byte, alg SignatureAlgorithm) (signatureInfo, error)
}

type payloadVerifier interface {
	verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type genericSigner struct {
	recipients []recipientSigInfo
}

type recipientSigInfo struct {
	sigAlg   SignatureAlgorithm
	signer   payloadSigner
	verifier payloadVerifier
}

// NewSigner creates an appropriate signer based on the key type
func NewSigner(alg SignatureAlgorithm, signingKey interface{}) (Signer, error) {
	// NewMultiSigner never fails (currently)
	signer := NewMultiSigner()

	err := signer.AddRecipient(alg, signingKey)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// NewMultiSigner creates a signer for multiple recipients
func NewMultiSigner() MultiSigner {
	return &genericSigner{
		recipients: []recipientSigInfo{},
	}
}

// newVerifier creates a verifier based on the key type
func newVerifier(verificationKey interface{}) (payloadVerifier, error) {
	switch verificationKey := verificationKey.(type) {
	case *rsa.PublicKey:
		return &rsaEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case *ecdsa.PublicKey:
		return &ecEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case []byte:
		return &symmetricMac{
			key: verificationKey,
		}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

func (ctx *genericSigner) AddRecipient(alg SignatureAlgorithm, signingKey interface{}) error {
	var err error
	var recipient recipientSigInfo

	switch signingKey := signingKey.(type) {
	case *rsa.PrivateKey:
		recipient, err = newRSASigner(alg, signingKey)
	case *ecdsa.PrivateKey:
		recipient, err = newECDSASigner(alg, signingKey)
	case []byte:
		recipient, err = newSymmetricSigner(alg, signingKey)
	default:
		return ErrUnsupportedKeyType
	}

	if err != nil {
		return err
	}

	ctx.recipients = append(ctx.recipients, recipient)
	return nil
}

func (ctx *genericSigner) Sign(payload []byte) (*JsonWebSignature, error) {
	obj := &JsonWebSignature{}
	obj.payload = payload
	obj.signatures = make([]signatureInfo, len(ctx.recipients))

	for i, recipient := range ctx.recipients {
		protected := map[string]interface{}{
			"alg": string(recipient.sigAlg),
		}

		serializedProtected := mustSerializeJSON(protected)

		input := []byte(fmt.Sprintf("%s.%s",
			base64URLEncode(serializedProtected),
			base64URLEncode(payload)))

		signatureInfo, err := recipient.signer.signPayload(input, recipient.sigAlg)
		if err != nil {
			return nil, err
		}

		signatureInfo.protected = protected
		obj.signatures[i] = signatureInfo
	}

	return obj, nil
}

// Verify validates the signature on the object and returns the payload.
func (obj JsonWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
	verifier, err := newVerifier(verificationKey)
	if err != nil {
		return nil, err
	}

	for _, signature := range obj.signatures {
		if _, critPresent := signature.getHeader("crit"); critPresent {
			// Unsupported crit header
			continue
		}

		input := obj.computeAuthData(&signature)

		algValue, algPresent := signature.getHeader("alg")
		if !algPresent {
			continue
		}

		if algValue, ok := algValue.(string); ok {
			alg := SignatureAlgorithm(algValue)
			err := verifier.verifyPayload(input, signature.signature, alg)
			if err == nil {
				return obj.payload, nil
			}
		} else {
			return nil, fmt.Errorf("square/go-jose: invalid alg header")
		}
	}

	return nil, ErrCryptoFailure
}
