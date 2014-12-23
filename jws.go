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
	"encoding/json"
	"fmt"
	"strings"
)

// rawJsonWebSignature represents a raw JWS JSON object. Used for parsing/serializing.
type rawJsonWebSignature struct {
	Payload    *byteBuffer        `json:"payload,omitempty"`
	Signatures []rawSignatureInfo `json:"signatures,omitempty"`
	Protected  *byteBuffer        `json:"protected,omitempty"`
	Header     *rawHeader         `json:"header,omitempty"`
	Signature  *byteBuffer        `json:"signature,omitempty"`
}

// rawSignatureInfo represents a single JWS signature over the JWS payload and protected header.
type rawSignatureInfo struct {
	Protected *byteBuffer `json:"protected,omitempty"`
	Header    *rawHeader  `json:"header,omitempty"`
	Signature *byteBuffer `json:"signature,omitempty"`
}

// JsonWebSignature represents a signed JWS object after parsing.
type JsonWebSignature struct {
	payload    []byte
	signatures []signatureInfo
}

// signatureInfo represents a single JWS signature over the JWS payload and protected header after parsing.
type signatureInfo struct {
	protected *rawHeader
	header    *rawHeader
	signature []byte
	original  *rawSignatureInfo
}

// ParseSigned parses an encrypted message in compact or full serialization format.
func ParseSigned(input string) (*JsonWebSignature, error) {
	input = stripWhitespace(input)
	if strings.HasPrefix(input, "{") {
		return parseSignedFull(input)
	}

	return parseSignedCompact(input)
}

// Get a header value
func (sig signatureInfo) mergedHeaders() rawHeader {
	out := rawHeader{}
	out.merge(sig.protected)
	out.merge(sig.header)
	return out
}

// Compute data to be signed
func (obj JsonWebSignature) computeAuthData(signature *signatureInfo) []byte {
	var serializedProtected string

	if signature.original == nil {
		serializedProtected = base64URLEncode(mustSerializeJSON(signature.protected))
	} else {
		serializedProtected = signature.original.Protected.base64()
	}

	return []byte(fmt.Sprintf("%s.%s",
		serializedProtected,
		base64URLEncode(obj.payload)))
}

// parseSignedFull parses a message in full format.
func parseSignedFull(input string) (*JsonWebSignature, error) {
	var parsed rawJsonWebSignature
	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		return nil, err
	}

	if parsed.Payload == nil {
		return nil, fmt.Errorf("square/go-jose: missing payload in JWS message")
	}

	obj := &JsonWebSignature{}
	obj.payload = parsed.Payload.bytes()
	obj.signatures = make([]signatureInfo, len(parsed.Signatures))

	if len(parsed.Signatures) == 0 {
		// No signatures array, must be flattened serialization
		signature := signatureInfo{}
		if parsed.Protected != nil && len(parsed.Protected.bytes()) > 0 {
			signature.protected = &rawHeader{}
			err = json.Unmarshal(parsed.Protected.bytes(), signature.protected)
			if err != nil {
				return nil, err
			}
		}

		signature.header = parsed.Header
		signature.signature = parsed.Signature.bytes()
		obj.signatures = append(obj.signatures, signature)
	}

	for i, sig := range parsed.Signatures {
		if sig.Protected != nil && len(sig.Protected.bytes()) > 0 {
			obj.signatures[i].protected = &rawHeader{}
			err = json.Unmarshal(sig.Protected.bytes(), obj.signatures[i].protected)
			if err != nil {
				return nil, err
			}
		}

		obj.signatures[i].signature = sig.Signature.bytes()

		// Copy value of sig
		original := sig

		obj.signatures[i].header = sig.Header
		obj.signatures[i].original = &original
	}

	return obj, nil
}

// parseSignedCompact parses a message in compact format.
func parseSignedCompact(input string) (*JsonWebSignature, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("square/go-jose: compact JWS format must have three parts")
	}

	rawProtected, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}

	var protected rawHeader
	err = json.Unmarshal(rawProtected, &protected)
	if err != nil {
		return nil, err
	}

	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}

	return &JsonWebSignature{
		payload: payload,
		signatures: []signatureInfo{
			signatureInfo{
				protected: &protected,
				signature: signature,
				original: &rawSignatureInfo{
					Protected: newBuffer(rawProtected),
					Signature: newBuffer(signature),
				},
			},
		},
	}, nil
}

// CompactSerialize serializes an object using the compact serialization format.
func (obj JsonWebSignature) CompactSerialize() (string, error) {
	if len(obj.signatures) > 1 || obj.signatures[0].header != nil {
		return "", ErrNotSupported
	}

	serializedProtected := mustSerializeJSON(obj.signatures[0].protected)

	return fmt.Sprintf(
		"%s.%s.%s",
		base64URLEncode(serializedProtected),
		base64URLEncode(obj.payload),
		base64URLEncode(obj.signatures[0].signature)), nil
}

// FullSerialize serializes an object using the full JSON serialization format.
func (obj JsonWebSignature) FullSerialize() string {
	raw := rawJsonWebSignature{
		Payload: newBuffer(obj.payload),
	}

	if len(obj.signatures) == 1 {
		serializedProtected := mustSerializeJSON(obj.signatures[0].protected)
		raw.Protected = newBuffer(serializedProtected)
		raw.Header = obj.signatures[0].header
		raw.Signature = newBuffer(obj.signatures[0].signature)
	} else {
		raw.Signatures = make([]rawSignatureInfo, len(obj.signatures))
		for i, signature := range obj.signatures {
			serializedProtected := mustSerializeJSON(signature.protected)

			raw.Signatures[i] = rawSignatureInfo{
				Protected: newBuffer(serializedProtected),
				Header:    signature.header,
				Signature: newBuffer(signature.signature),
			}
		}
	}

	return string(mustSerializeJSON(raw))
}
