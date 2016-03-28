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

package validator

import (
	"time"

	"github.com/square/go-jose/jwt"
)

const (
	DefaultExpLeeway = 1.0 * time.Minute
	DefaultNbfLeeway = 1.0 * time.Minute
	NoLeeway         = -1
)

type Validator struct {
	p Params
}

type Params struct {
	Issuer    string
	Subject   string
	Audience  []string
	ID        string
	ExpLeeway time.Duration
	NbfLeeway time.Duration
}

func New(p Params) *Validator {
	if p.ExpLeeway == 0 {
		p.ExpLeeway = DefaultExpLeeway
	}

	if p.NbfLeeway == 0 {
		p.NbfLeeway = DefaultNbfLeeway
	}

	if p.ExpLeeway == NoLeeway {
		p.ExpLeeway = 0
	}

	if p.NbfLeeway == 0 {
		p.NbfLeeway = 0
	}

	return &Validator{p}
}

func (v *Validator) Validate(c jwt.Claims, now time.Time) error {
	e := &v.p
	if e.Issuer != "" && e.Issuer != c.Issuer {
		return ErrInvalidIssuer
	}

	if e.Subject != "" && e.Subject != c.Subject {
		return ErrInvalidSubject
	}

	if e.ID != "" && e.ID != c.ID {
		return ErrInvalidID
	}

	if len(e.Audience) != 0 {
		if len(e.Audience) != len(c.Audience) {
			return ErrInvalidAudience
		}

		for i, a := range e.Audience {
			if a != c.Audience[i] {
				return ErrInvalidAudience
			}
		}
	}

	if now.Add(-e.NbfLeeway).Before(c.NotBefore) {
		return ErrInvalidNotBefore
	}

	if now.Add(e.ExpLeeway).After(c.Expiry) {
		return ErrInvalidExpiry
	}

	return nil
}
