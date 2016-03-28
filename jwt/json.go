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
	"strconv"
	"time"

	"github.com/square/go-jose"
)

type Audience []string

func (s *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := jose.UnmarshalJSON(b, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		*s = append(*s, v)
	case []interface{}:
		a := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return ErrUnmarshalAudience
			}
			a[i] = s
		}
		*s = a
	default:
		return ErrUnmarshalAudience
	}

	return nil
}

type NumericDate int64

func TimeToNumericDate(t time.Time) NumericDate {
	// zero value for a Time is defined as January 1, *year 1*, 00:00:00
	if t.IsZero() {
		return NumericDate(0)
	}

	return NumericDate(t.Unix())
}

func (n NumericDate) MarshalJSON() ([]byte, error) {
	s := strconv.FormatInt(int64(n), 10)
	return []byte(s), nil
}

func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := string(b)

	sec, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		*n = NumericDate(sec)
		return nil
	}

	f, err := strconv.ParseFloat(s, 64)
	if err == nil {
		*n = NumericDate(f)
	}

	return ErrUnmarshalNumericDate
}

func (n NumericDate) Time() time.Time {
	return time.Unix(int64(n), 0)
}
