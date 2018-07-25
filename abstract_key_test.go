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
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	JwsPayload = `{"key":"value"}`
)

var Key = []byte{0x01, 0x02, 0x03, 0x04, 0x05}
var WrongKey = []byte{0x06, 0x07, 0x08}

var serialized string

func TestSignWithAbstractSigner(t *testing.T) {
	payload := []byte(JwsPayload)
	key, _ := NewXorTestKey(Key)
	if signer, err := NewSigner(PS256, key); err != nil {
		t.Errorf("Error creating signer: %q", err)
	} else if _, err := signer.Sign(payload); err != ErrUnsupportedAlgorithm {
		t.Errorf("Error allowing an unsupported algorithm: %q", PS256)
	} else if signer, err := NewSigner(TestXorAlg, key); err != nil {
		t.Errorf("Error creating signer: %q", err)
	} else if jws, err := signer.Sign(payload); err != nil {
		t.Errorf("Error signing: %q", err)
	} else if serialized, err = jws.CompactSerialize(); err != nil {
		t.Fatalf("Error serializing: %q", err)
	} else {
		sigAsBytes, _ := base64URLDecode(string(jws.Signatures[0].Signature))
		for i, v := range sigAsBytes {
			if byte(v)^Key[i] != payload[i] {
				t.Fatalf("Verification error at index %d. Got 0x%X expected 0x%X", i, byte(v), payload[i]^Key[i])
			}
		}

		tokenParts := strings.Split(serialized, ".")
		if len(tokenParts) != 3 {
			t.Fatalf("Error: malformed token.  Expected 3 parts, got %d", len(tokenParts))
		}
		expectedAlgClaim := fmt.Sprintf(`"alg":"%s"`, TestXorAlg)
		expectedKidClaim := fmt.Sprintf(`"kid":"%s"`, TestXorKeyId)
		headerAsBytes, _ := base64URLDecode(string(tokenParts[0]))
		header := string(headerAsBytes)
		if !strings.Contains(header, expectedAlgClaim) {
			t.Fatalf("Error: Expected algorithm claim %q but header was %q", expectedAlgClaim, header)
		} else if !strings.Contains(header, expectedKidClaim) {
			t.Fatalf("Error: Expected kid claim %q but header was %q", expectedKidClaim, header)
		}

	}
}

func TestVerifyWithAbstractVerifier(t *testing.T) {
	// Pre create the compact serialized token if needed
	if serialized == "" {
		TestSignWithAbstractSigner(t)
	}

	key, _ := NewXorTestKey(Key)
	wrongKey, _ := NewXorTestKey(WrongKey)
	if jws, err := ParseSigned(serialized); err != nil {
		t.Fatalf("Error parsing serialized JWT: %q", err)
	} else if _, err := jws.Verify(key); err != nil {
		t.Errorf("Error verifying: %q", err)
	} else if _, err := jws.Verify(wrongKey); err == nil {
		t.Error("Error tampered JWS passes verification")
	}
}

const (
	TestXorAlg   = SignatureAlgorithm("testXorAlg") // An unsupported algorithm simply used for test purposes
	TestXorKeyId = "testXorKeyId"
)

// For the purposes of test and to provide an example of using an unsupported signing mechanism and key type this
// signer/verifier uses a simple XOR of the first options.bytesToXor with the key
type TestXorSignerVerifier struct {
	key []byte
}

func (ctx *TestXorSignerVerifier) KeyID() string {
	return TestXorKeyId
}

func (ctx *TestXorSignerVerifier) SignPayload(payload []byte, algorithm SignatureAlgorithm) (signature []byte, err error) {
	if algorithm != TestXorAlg {
		err = ErrUnsupportedAlgorithm
	} else {
		bytesToXor := len(ctx.key)
		if bytesToXor > len(payload) {
			bytesToXor = len(payload)
		}

		signature = make([]byte, bytesToXor)
		for i, v := range payload[:bytesToXor] {
			signature[i] = byte(v) ^ ctx.key[i]
		}
	}
	return
}

func (ctx *TestXorSignerVerifier) Verify(payload []byte, signature []byte, algorithm SignatureAlgorithm) (err error) {
	if algorithm != TestXorAlg {
		err = ErrUnsupportedAlgorithm
	} else {
		for i, v := range signature {
			if byte(v)^ctx.key[i] != payload[i] {
				return errors.New("Verification error")
			}
		}
	}
	return
}

func NewXorTestKey(key []byte) (signerVerifier *TestXorSignerVerifier, err error) {
	return &TestXorSignerVerifier{
		key: key,
	}, nil
}
