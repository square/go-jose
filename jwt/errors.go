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

package jwt

import "errors"

var ErrUnmarshalAudience = errors.New("Expected string or array value to unmarshal Audience")
var ErrUnmarshalNumericDate = errors.New("Expected number value to unmarshal NumericDate")

var ErrInvalidIssuer = errors.New("JWT: invalid issuer")
var ErrInvalidSubject = errors.New("JWT: invalid subject")
var ErrInvalidAudience = errors.New("JWT: invalid audience")
var ErrInvalidID = errors.New("JWT: invalid ID")
var ErrInvalidIssuedAt = errors.New("JWT: token issued before minimum issue date")
var ErrInvalidNotBefore = errors.New("JWT: token used before its valid date in claim <nbf>")
var ErrInvalidExpiry = errors.New("JWT: token used after its valid date in claim <exp>")
