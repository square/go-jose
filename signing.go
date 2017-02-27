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
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// NonceSource represents a source of random nonces to go into JWS objects
type NonceSource interface {
	Nonce() (string, error)
}

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer interface {
	Sign(payload []byte) (*JSONWebSignature, error)
	Options() SignerOptions
}

// SigningKey represents an algorithm/key used to sign a message.
type SigningKey struct {
	Algorithm SignatureAlgorithm
	Key       interface{}
}

// SignerOptions represents options that can be set when creating signers.
type SignerOptions struct {
	NonceSource NonceSource
	EmbedJWK    bool
	Type        ContentType
	ContentType ContentType
}

type payloadSigner interface {
	signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error)
}

type payloadVerifier interface {
	verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type genericSigner struct {
	recipients  []recipientSigInfo
	nonceSource NonceSource
	embedJWK    bool
	typ         ContentType
	contentType ContentType
}

type recipientSigInfo struct {
	sigAlg    SignatureAlgorithm
	publicKey *JSONWebKey
	signer    payloadSigner
}

// NewSigner creates an appropriate signer based on the key type
func NewSigner(sig SigningKey, opts *SignerOptions) (Signer, error) {
	return NewMultiSigner([]SigningKey{sig}, opts)
}

// NewMultiSigner creates a signer for multiple recipients
func NewMultiSigner(sigs []SigningKey, opts *SignerOptions) (Signer, error) {
	signer := &genericSigner{recipients: []recipientSigInfo{}}

	if opts != nil {
		signer.nonceSource = opts.NonceSource
		signer.embedJWK = opts.EmbedJWK
		signer.typ = opts.Type
		signer.contentType = opts.ContentType
	}

	for _, sig := range sigs {
		err := signer.addRecipient(sig.Algorithm, sig.Key)
		if err != nil {
			return nil, err
		}
	}

	return signer, nil
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
	case JSONWebKey:
		return newVerifier(verificationKey.Key)
	case *JSONWebKey:
		return newVerifier(verificationKey.Key)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

func (ctx *genericSigner) addRecipient(alg SignatureAlgorithm, signingKey interface{}) error {
	recipient, err := makeJWSRecipient(alg, signingKey)
	if err != nil {
		return err
	}

	ctx.recipients = append(ctx.recipients, recipient)
	return nil
}

func makeJWSRecipient(alg SignatureAlgorithm, signingKey interface{}) (recipientSigInfo, error) {
	switch signingKey := signingKey.(type) {
	case *rsa.PrivateKey:
		return newRSASigner(alg, signingKey)
	case *ecdsa.PrivateKey:
		return newECDSASigner(alg, signingKey)
	case []byte:
		return newSymmetricSigner(alg, signingKey)
	case JSONWebKey:
		return newJWKSigner(alg, signingKey)
	case *JSONWebKey:
		return newJWKSigner(alg, *signingKey)
	default:
		return recipientSigInfo{}, ErrUnsupportedKeyType
	}
}

func newJWKSigner(alg SignatureAlgorithm, signingKey JSONWebKey) (recipientSigInfo, error) {
	recipient, err := makeJWSRecipient(alg, signingKey.Key)
	if err != nil {
		return recipientSigInfo{}, err
	}
	recipient.publicKey = &signingKey
	return recipient, nil
}

func (ctx *genericSigner) Sign(payload []byte) (*JSONWebSignature, error) {
	obj := &JSONWebSignature{}
	obj.payload = payload
	obj.Signatures = make([]Signature, len(ctx.recipients))

	for i, recipient := range ctx.recipients {
		protected := &rawHeader{
			Alg: string(recipient.sigAlg),
			Typ: string(ctx.typ),
			Cty: string(ctx.contentType),
		}

		if recipient.publicKey != nil {
			if ctx.embedJWK {
				protected.Jwk = recipient.publicKey
			}
			protected.Kid = recipient.publicKey.KeyID
			protected.X5u = recipient.publicKey.X509URL
			protected.X5t = recipient.publicKey.X509Thumb
			protected.X5tSHA256 = recipient.publicKey.X509ThumbSHA256
			protected.X5c = recipient.publicKey.Certificates
		}

		if ctx.nonceSource != nil {
			nonce, err := ctx.nonceSource.Nonce()
			if err != nil {
				return nil, fmt.Errorf("square/go-jose: Error generating nonce: %v", err)
			}
			protected.Nonce = nonce
		}

		serializedProtected := mustSerializeJSON(protected)

		input := []byte(fmt.Sprintf("%s.%s",
			base64.RawURLEncoding.EncodeToString(serializedProtected),
			base64.RawURLEncoding.EncodeToString(payload)))

		signatureInfo, err := recipient.signer.signPayload(input, recipient.sigAlg)
		if err != nil {
			return nil, err
		}

		signatureInfo.protected = protected
		obj.Signatures[i] = signatureInfo
	}

	return obj, nil
}

func (ctx *genericSigner) Options() SignerOptions {
	return SignerOptions{
		NonceSource: ctx.nonceSource,
		EmbedJWK:    ctx.embedJWK,
		Type:        ctx.typ,
		ContentType: ctx.contentType,
	}
}

// Verify validates the signature on the object and returns the payload.
// This function does not support multi-signature, if you desire multi-sig
// verification use VerifyMulti instead.
//
// Be careful when verifying signatures based on embedded JWKs inside the
// payload header. You cannot assume that the key received in a payload is
// trusted.
func (obj JSONWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
	verifier, err := newVerifier(verificationKey)
	if err != nil {
		return nil, err
	}

	if len(obj.Signatures) > 1 {
		return nil, errors.New("square/go-jose: too many signatures in payload; expecting only one")
	}

	signature := obj.Signatures[0]
	headers := signature.mergedHeaders()
	if len(headers.Crit) > 0 {
		// Unsupported crit header
		return nil, ErrCryptoFailure
	}

	input := obj.computeAuthData(&signature)
	alg := SignatureAlgorithm(headers.Alg)
	err = verifier.verifyPayload(input, signature.Signature, alg)
	if err == nil {
		return obj.payload, nil
	}

	if err := verifyCerts(&headers); err != nil {
		return nil, err
	}

	return nil, ErrCryptoFailure
}

// VerifyMulti validates (one of the multiple) signatures on the object and
// returns the index of the signature that was verified, along with the signature
// object and the payload. We return the signature and index to guarantee that
// callers are getting the verified value.
func (obj JSONWebSignature) VerifyMulti(verificationKey interface{}) (int, Signature, []byte, error) {
	verifier, err := newVerifier(verificationKey)
	if err != nil {
		return -1, Signature{}, nil, err
	}

	for i, signature := range obj.Signatures {
		headers := signature.mergedHeaders()
		if len(headers.Crit) > 0 {
			// Unsupported crit header
			continue
		}

		input := obj.computeAuthData(&signature)
		alg := SignatureAlgorithm(headers.Alg)
		if err := verifier.verifyPayload(input, signature.Signature, alg); err != nil {
			continue
		}

		if err := verifyCerts(&headers); err != nil {
			continue
		}

		return i, signature, obj.payload, nil
	}

	return -1, Signature{}, nil, ErrCryptoFailure
}

func verifyCerts(data *rawHeader) error {
	if len(data.X5c) == 0 {
		return nil
	}

	pub := data.X5c[0]
	if data.X5t != "" && X509Thumbprint(pub) != data.X5t {
		return ErrCryptoFailure
	}
	if data.X5tSHA256 != "" && X509ThumbprintSHA256(pub) != data.X5tSHA256 {
		return ErrCryptoFailure
	}

	var im *x509.CertPool
	if len(data.X5c) > 1 {
		im = x509.NewCertPool()
		for _, cert := range data.X5c[1:] {
			im.AddCert(cert)
		}
	}

	_, err := pub.Verify(x509.VerifyOptions{Intermediates: im})
	if err != nil {
		return ErrCryptoFailure
	}
	return nil
}
