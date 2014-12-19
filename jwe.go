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

// rawJweObject represents a raw JWE JSON object. Used for parsing/serializing.
type rawJweObject struct {
	Protected    string                 `json:"protected,omitempty"`
	Unprotected  map[string]interface{} `json:"unprotected,omitempty"`
	Header       map[string]interface{} `json:"header,omitempty"`
	Recipients   []rawRecipientInfo     `json:"recipients,omitempty"`
	Aad          string                 `json:"aad,omitempty"`
	EncryptedKey string                 `json:"encrypted_key,omitempty"`
	Iv           string                 `json:"iv,omitempty"`
	Ciphertext   string                 `json:"ciphertext,omitempty"`
	Tag          string                 `json:"tag,omitempty"`
}

// rawRecipientInfo represents a raw JWE Per-Recipient Header JSON object. Used for parsing/serializing.
type rawRecipientInfo struct {
	Header       map[string]interface{} `json:"header,omitempty"`
	EncryptedKey string                 `json:"encrypted_key,omitempty"`
}

// JweObject represents an encrypted JWE object after parsing.
type JweObject struct {
	protected, unprotected   map[string]interface{}
	recipients               []recipientInfo
	aad, iv, ciphertext, tag []byte
	original                 *rawJweObject
}

// recipientInfo represents a raw JWE Per-Recipient Header JSON object after parsing.
type recipientInfo struct {
	header       map[string]interface{}
	encryptedKey []byte
}

// GetAuthData retrieves the (optional) authenticated data attached to the object.
func (obj JweObject) GetAuthData() []byte {
	if obj.aad != nil {
		out := make([]byte, len(obj.aad))
		copy(out, obj.aad)
		return out
	}

	return nil
}

// Get the additional authenticated data from a JWE object.
func (obj JweObject) computeAuthData() []byte {
	var protected string

	if obj.original != nil {
		protected = obj.original.Protected
	} else {
		marshaled, err := json.Marshal(obj.protected)
		if err != nil {
			// We have full control over the input, so this should never happen.
			panic("Error when serializing message header")
		}
		protected = base64URLEncode(marshaled)
	}

	output := []byte(protected)
	if obj.aad != nil {
		output = append(output, '.')
		output = append(output, []byte(base64URLEncode(obj.aad))...)
	}

	return output
}

// Get a header value from a JWE object.
func (obj JweObject) getHeader(name string, recipient *recipientInfo) (value interface{}, present bool) {
	value, present = obj.protected[name]

	if !present {
		value, present = obj.unprotected[name]
	}

	if !present && recipient != nil {
		value, present = recipient.header[name]
	}

	return
}

// ParseEncrypted parses an encrypted message in compact or full serialization format.
func ParseEncrypted(input string) (*JweObject, error) {
	input = stripWhitespace(input)
	if strings.HasPrefix(input, "{") {
		return parseEncryptedFull(input)
	}

	return parseEncryptedCompact(input)
}

// parseEncryptedFull parses a message in compact format.
func parseEncryptedFull(input string) (*JweObject, error) {
	var parsed rawJweObject
	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		return nil, err
	}

	obj := &JweObject{}
	obj.unprotected = parsed.Unprotected
	obj.original = &parsed

	rawProtected, err := base64URLDecode(parsed.Protected)
	if err != nil {
		return nil, err
	}

	if len(rawProtected) > 0 {
		obj.protected = make(map[string]interface{})
		err = json.Unmarshal(rawProtected, &obj.protected)
		if err != nil {
			return nil, err
		}
	}

	if len(parsed.Recipients) == 0 {
		encryptedKey, err := base64URLDecode(parsed.EncryptedKey)
		if err != nil {
			return nil, err
		}

		obj.recipients = []recipientInfo{
			recipientInfo{
				header:       parsed.Header,
				encryptedKey: encryptedKey,
			},
		}
	} else {
		obj.recipients = make([]recipientInfo, len(parsed.Recipients))
		for r := range parsed.Recipients {
			encryptedKey, err := base64URLDecode(parsed.Recipients[r].EncryptedKey)
			if err != nil {
				return nil, err
			}

			obj.recipients[r].header = parsed.Recipients[r].Header
			obj.recipients[r].encryptedKey = encryptedKey
		}
	}

	obj.iv, err = base64URLDecode(parsed.Iv)
	if err != nil {
		return nil, err
	}

	obj.ciphertext, err = base64URLDecode(parsed.Ciphertext)
	if err != nil {
		return nil, err
	}

	obj.tag, err = base64URLDecode(parsed.Tag)
	if err != nil {
		return nil, err
	}

	if parsed.Aad != "" {
		obj.aad, err = base64URLDecode(parsed.Aad)
		if err != nil {
			return nil, err
		}
	}

	_, encPresent := obj.getHeader("enc", nil)
	if !encPresent {
		return nil, fmt.Errorf("square/go-jose: invalid, missing enc header")
	}

	for _, recipient := range obj.recipients {
		_, algPresent := obj.getHeader("alg", &recipient)
		if !algPresent {
			return nil, fmt.Errorf("square/go-jose: invalid, missing alg header")
		}
	}

	return obj, nil
}

// parseEncryptedCompact parses a message in compact format.
func parseEncryptedCompact(input string) (*JweObject, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("square/go-jose: compact JWE format must have five parts")
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

	encryptedKey, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	iv, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64URLDecode(parts[3])
	if err != nil {
		return nil, err
	}

	tag, err := base64URLDecode(parts[4])
	if err != nil {
		return nil, err
	}

	_, algPresent := protected["alg"]
	_, encPresent := protected["enc"]
	if !algPresent || !encPresent {
		return nil, fmt.Errorf("square/go-jose: invalid, missing alg or enc header")
	}

	return &JweObject{
		protected: protected,
		recipients: []recipientInfo{
			recipientInfo{
				encryptedKey: encryptedKey,
			},
		},
		iv:         iv,
		ciphertext: ciphertext,
		tag:        tag,
		original: &rawJweObject{
			Protected:    parts[0],
			EncryptedKey: parts[1],
			Iv:           parts[2],
			Ciphertext:   parts[3],
			Tag:          parts[4],
		},
	}, nil
}

// CompactSerialize serializes an object using the compact serialization format.
func (obj JweObject) CompactSerialize() (string, error) {
	if len(obj.recipients) > 1 || len(obj.unprotected) > 0 || len(obj.recipients[0].header) > 0 {
		return "", ErrNotSupported
	}

	serializedProtected, err := json.Marshal(obj.protected)
	if err != nil {
		// We have full control over the input, so this should never happen.
		panic("Error when serializing message header")
	}

	return fmt.Sprintf(
		"%s.%s.%s.%s.%s",
		base64URLEncode(serializedProtected),
		base64URLEncode(obj.recipients[0].encryptedKey),
		base64URLEncode(obj.iv),
		base64URLEncode(obj.ciphertext),
		base64URLEncode(obj.tag)), nil
}

// FullSerialize serializes an object using the full JSON serialization format.
func (obj JweObject) FullSerialize() string {
	raw := rawJweObject{
		Unprotected:  obj.unprotected,
		Iv:           base64URLEncode(obj.iv),
		Ciphertext:   base64URLEncode(obj.ciphertext),
		EncryptedKey: base64URLEncode(obj.recipients[0].encryptedKey),
		Tag:          base64URLEncode(obj.tag),
		Recipients:   []rawRecipientInfo{},
	}

	if len(obj.recipients) > 1 {
		for _, recipient := range obj.recipients {
			info := rawRecipientInfo{
				Header:       recipient.header,
				EncryptedKey: base64URLEncode(recipient.encryptedKey),
			}
			raw.Recipients = append(raw.Recipients, info)
		}
	} else {
		// Use flattened serialization
		raw.Header = obj.recipients[0].header
		raw.EncryptedKey = base64URLEncode(obj.recipients[0].encryptedKey)
	}

	if obj.aad != nil {
		raw.Aad = base64URLEncode(obj.aad)
	}

	if len(obj.protected) > 0 {
		serializedProtected, err := json.Marshal(obj.protected)
		if err != nil {
			// We have full control over the input, so this should never happen.
			panic("Error when serializing message header")
		}
		raw.Protected = base64URLEncode(serializedProtected)
	}

	message, err := json.Marshal(raw)
	if err != nil {
		// We have full control over the input, so this should never happen.
		panic("Error when serializing full message")
	}

	return string(message)
}
