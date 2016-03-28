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

// NumericDate represents JSON date as number value of seconds from 1st Jan 1970
// JSON value can be either integer or float
type NumericDate int64

// TimeToNumericDate converts time.Time value into NumericDate
func TimeToNumericDate(t time.Time) NumericDate {
	// zero value for a Time is defined as January 1, *year 1*, 00:00:00
	if t.IsZero() {
		return NumericDate(0)
	}

	return NumericDate(t.Unix())
}

// MarshalJSON serializes the given date into its JSON representation
func (n NumericDate) MarshalJSON() ([]byte, error) {
	s := strconv.FormatInt(int64(n), 10)
	return []byte(s), nil
}

// UnmarshalJSON reads a date from its JSON representation
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

// Time returns time.Time representation of NumericDate
func (n NumericDate) Time() time.Time {
	return time.Unix(int64(n), 0)
}

type audience []string

func (s *audience) UnmarshalJSON(b []byte) error {
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
