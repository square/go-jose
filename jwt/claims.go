/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
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

package jwt

// Claims represents public claim values (as specified in RFC 7519).
type Claims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  Audience    `json:"aud,omitempty"`
	Expiry    NumericDate `json:"exp,omitempty"`
	NotBefore NumericDate `json:"nbf,omitempty"`
	IssuedAt  NumericDate `json:"iat,omitempty"`
	ID        string      `json:"jti,omitempty"`
}
