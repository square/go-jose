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
	Payload    string             `json:"payload,omitempty"`
	Signatures []rawSignatureInfo `json:"signatures,omitempty"`
}

// rawSignatureInfo represents a single JWS signature over the JWS payload and protected header.
type rawSignatureInfo struct {
	Protected string                 `json:"protected,omitempty"`
	Header    map[string]interface{} `json:"header,omitempty"`
	Signature string                 `json:"signature,omitempty"`
}

// JsonWebSignature represents a signed JWS object after parsing.
type JsonWebSignature struct {
	payload    []byte
	signatures []signatureInfo
}

// signatureInfo represents a single JWS signature over the JWS payload and protected header after parsing.
type signatureInfo struct {
	protected map[string]interface{}
	header    map[string]interface{}
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
func (sig signatureInfo) getHeader(name string) (value interface{}, present bool) {
	value, present = sig.protected[name]

	if !present {
		value, present = sig.header[name]
	}

	return
}

// Compute data to be signed
func (obj JsonWebSignature) computeAuthData(signature *signatureInfo) []byte {
	var serializedProtected string

	if signature.original == nil {
		serializedProtected = base64URLEncode(serializeJSONChecked(signature.protected))
	} else {
		serializedProtected = signature.original.Protected
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

	obj := &JsonWebSignature{}

	obj.payload, err = base64URLDecode(parsed.Payload)
	if err != nil {
		return nil, err
	}

	if len(parsed.Signatures) == 0 {
		return nil, fmt.Errorf("square/go-jose: JWS object did not have signatures")
	}

	obj.signatures = make([]signatureInfo, len(parsed.Signatures))
	for i, sig := range parsed.Signatures {
		rawProtected, err := base64URLDecode(sig.Protected)
		if err != nil {
			return nil, err
		}

		if len(rawProtected) > 0 {
			obj.signatures[i].protected = make(map[string]interface{})
			err = json.Unmarshal(rawProtected, &obj.signatures[i].protected)
			if err != nil {
				return nil, err
			}
		}

		obj.signatures[i].signature, err = base64URLDecode(sig.Signature)
		if err != nil {
			return nil, err
		}

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

	var protected map[string]interface{}
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
				protected: protected,
				signature: signature,
				original: &rawSignatureInfo{
					Protected: parts[0],
					Signature: parts[2],
				},
			},
		},
	}, nil
}

// CompactSerialize serializes an object using the compact serialization format.
func (obj JsonWebSignature) CompactSerialize() (string, error) {
	if len(obj.signatures) > 1 || len(obj.signatures[0].header) > 0 {
		return "", ErrNotSupported
	}

	serializedProtected := serializeJSONChecked(obj.signatures[0].protected)

	return fmt.Sprintf(
		"%s.%s.%s",
		base64URLEncode(serializedProtected),
		base64URLEncode(obj.payload),
		base64URLEncode(obj.signatures[0].signature)), nil
}

// FullSerialize serializes an object using the full JSON serialization format.
func (obj JsonWebSignature) FullSerialize() string {
	raw := rawJsonWebSignature{
		Payload:    base64URLEncode(obj.payload),
		Signatures: make([]rawSignatureInfo, len(obj.signatures)),
	}

	for i, signature := range obj.signatures {
		serializedProtected := serializeJSONChecked(signature.protected)

		raw.Signatures[i] = rawSignatureInfo{
			Protected: base64URLEncode(serializedProtected),
			Header:    signature.header,
			Signature: base64URLEncode(signature.signature),
		}
	}

	return string(serializeJSONChecked(raw))
}
