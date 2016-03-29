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

var ErrMergeObjects = errors.New("Expected type serializable to JSON object")

// ErrUnmarshalAudience indicates that aud claim could not be unmarshalled
var ErrUnmarshalAudience = errors.New("Expected string or array value to unmarshal Audience")

// ErrUnmarshalNumericDate indicates that JWT NumericDate could not be unmarshalled
var ErrUnmarshalNumericDate = errors.New("Expected number value to unmarshal NumericDate")

// ErrInvalidClaims indicates that claims argument is invalid
var ErrInvalidClaims = errors.New("Expected non-nil struct pointer")

// ErrInvalidIssuer indicates invalid iss claim
var ErrInvalidIssuer = errors.New("JWT: invalid issuer")

// ErrInvalidSubject indicates invalid sub claim
var ErrInvalidSubject = errors.New("JWT: invalid subject")

// ErrInvalidAudience indicated invalid aud claim
var ErrInvalidAudience = errors.New("JWT: invalid audience")

// ErrInvalidID indicates invalid jti claim
var ErrInvalidID = errors.New("JWT: invalid ID")

// ErrNotValidYet indicates that token is used before time indicated in nbf claim
var ErrNotValidYet = errors.New("JWT: token not valid yet")

// ErrExpired indicates that token is used after expiry time indicated in exp claim
var ErrExpired = errors.New("JWT: token is expired")
