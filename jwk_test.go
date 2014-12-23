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
	"testing"
)

func TestParseInvalidKeys(t *testing.T) {
	invalids := []string{
		`{XXX`,
		`{"kty":[]}`,
		`{"kty":"EC","crv":"P-256","x":"###","y":""}`,
		`{"kty":"EC","crv":"P-256","x":"","y":"###"}`,
	}

	for _, invalid := range invalids {
		var jwk rawJsonWebKey
		err := json.Unmarshal([]byte(invalid), &jwk)
		if err == nil {
			t.Error("parser incorrectly parsed invalid key", jwk)
		}
	}
}

func TestParseInvalidECKeys(t *testing.T) {
	invalids := []string{
		`{"kty":"RSA"}`,
		`{"kty":"EC","crv":"XXX"}`,
		`{"kty":"EC","crv":"P-256","x":""}`,
	}

	for _, invalid := range invalids {
		var jwk rawJsonWebKey
		json.Unmarshal([]byte(invalid), &jwk)
		_, err := jwk.ecPublicKey()
		if err == nil {
			t.Error("ec parser incorrectly parsed invalid key", jwk)
		}
	}
}
