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
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/square/go-jose"
)

// NumericDate represents JSON date as number value of seconds from 1st Jan 1970
// JSON value can be either integer or float
type NumericDate float64

// TimeToNumericDate converts time.Time value into NumericDate
func TimeToNumericDate(t time.Time) NumericDate {
	// zero value for a Time is defined as January 1, *year 1*, 00:00:00
	if t.IsZero() {
		return NumericDate(0)
	}

	i := float64(t.Unix())
	f := float64(t.UnixNano()%int64(time.Second)) / float64(time.Second)

	return NumericDate(i + f)
}

// MarshalJSON serializes the given date into its JSON representation
func (n NumericDate) MarshalJSON() ([]byte, error) {
	i, f := math.Modf(float64(n))
	if f == 0.0 {
		return []byte(strconv.FormatInt(int64(i), 10)), nil
	}

	s := strconv.FormatFloat(float64(n), 'G', -1, 64)
	return []byte(s), nil
}

// UnmarshalJSON reads a date from its JSON representation
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := string(b)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return ErrUnmarshalNumericDate
	}

	*n = NumericDate(f)
	return nil
}

// Time returns time.Time representation of NumericDate
func (n NumericDate) Time() time.Time {
	i, f := math.Modf(float64(n))
	return time.Unix(int64(i), int64(f*float64(time.Second)))
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

var claimsType = reflect.TypeOf((*Claims)(nil)).Elem()

func publicClaims(i interface{}) *Claims {
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return nil
	}

	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return nil
	}

	f := v.FieldByName("Claims")
	if !f.IsValid() || f.Type() != claimsType {
		return nil
	}

	c := f.Addr().Interface().(*Claims)
	return c
}

func marshalClaims(i interface{}) ([]byte, error) {
	// i is of jwt.Claims type
	if c, ok := i.(Claims); ok {
		return c.marshalJSON()
	}

	public := publicClaims(i)
	// i doesn't contain nested jwt.Claims
	if public == nil {
		return jose.MarshalJSON(i)
	}

	// marshal jwt.Claims
	b1, err := public.marshalJSON()
	if err != nil {
		return nil, err
	}

	// marshal private claims
	b2, err := jose.MarshalJSON(i)
	if err != nil {
		return nil, err
	}

	// merge claims
	r := make([]byte, len(b1)+len(b2)-1)
	copy(r, b1)
	r[len(b1)-1] = ','
	copy(r[len(b1):], b2[1:])

	return r, nil
}

func unmarshalClaims(b []byte, i interface{}) error {
	// i is of jwt.Claims type
	if c, ok := i.(*Claims); ok {
		return c.unmarshalJSON(b)
	}

	if err := jose.UnmarshalJSON(b, i); err != nil {
		return err
	}

	public := publicClaims(i)
	// unmarshal jwt.Claims
	if public != nil {
		if err := public.unmarshalJSON(b); err != nil {
			return err
		}
	}

	return nil
}
