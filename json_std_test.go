// +build std_json

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
	"testing"
)

type CaseInsensitive struct {
	A int `json:"TEST"`
}

func TestCaseInsensitiveJSON(t *testing.T) {
	raw := []byte(`{"test":42}`)
	var ci CaseInsensitive
	err := UnmarshalJSON(raw, &ci)
	if err != nil {
		t.Error(err)
	}

	if ci.A != 42 {
		t.Errorf("parsing JSON should be case-insensitive (got %v)", ci)
	}
}

func TestParseCaseInsensitiveJWE(t *testing.T) {
	invalidJWE := `{"protected":"eyJlbmMiOiJYWVoiLCJBTEciOiJYWVoifQo","encrypted_key":"QUJD","iv":"QUJD","ciphertext":"QUJD","tag":"QUJD"}`
	_, err := ParseEncrypted(invalidJWE)
	if err != nil {
		t.Error("Unable to parse message with case-invalid headers", invalidJWE)
	}
}

func TestParseCaseInsensitiveJWS(t *testing.T) {
	invalidJWS := `{"PAYLOAD":"CUJD","signatures":[{"protected":"e30","signature":"CUJD"}]}`
	_, err := ParseSigned(invalidJWS)
	if err != nil {
		t.Error("Unable to parse message with case-invalid headers", invalidJWS)
	}
}
