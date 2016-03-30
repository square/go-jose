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

import (
	"errors"
	"net/http"
)

const (
	// JWTGrantType is urn of JWT
	JWTGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// ErrGrantType indicates that grant_type form value was missing or invalid
var ErrGrantType = errors.New("Grant type invalid or missing from request")

// ErrNoToken indicates that assertion form value was missing
var ErrNoToken = errors.New("Token not specified in request")

// FromRequest retrieves token as described in RFC 7523
func FromRequest(r *http.Request, p func(string) (*JSONWebToken, error)) (*JSONWebToken, error) {
	if r.PostFormValue("grant_type") != JWTGrantType {
		return nil, ErrGrantType
	}

	raw := r.PostFormValue("assertion")
	if raw == "" {
		return nil, ErrNoToken
	}

	return p(raw)
}
