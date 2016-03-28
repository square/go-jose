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

import "time"

const (
	DefaultLeeway = 1.0 * time.Minute
	NoLeeway      = -1
)

type Expected struct {
	Issuer    string
	Subject   string
	Audience  []string
	ID        string
	Time      time.Time
	ExpLeeway time.Duration
	NbfLeeway time.Duration
}

func (c Claims) Validate(e Expected) error {
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

	if !e.Time.IsZero() && e.Time.Add(-leeway(e.NbfLeeway)).Before(c.NotBefore) {
		return ErrInvalidNotBefore
	}

	if !e.Time.IsZero() && e.Time.Add(leeway(e.ExpLeeway)).After(c.Expiry) {
		return ErrInvalidExpiry
	}

	return nil
}

func leeway(l time.Duration) time.Duration {
	switch l {
	case 0:
		return DefaultLeeway
	case NoLeeway:
		return 0
	default:
		return l
	}
}
