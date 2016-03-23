package jwt

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"time"
)

type StringOrArray []string

func (s *StringOrArray) UnmarshalJSON(b []byte) error {
	r := bytes.NewReader(b)
	d := json.NewDecoder(r)

	t, err := d.Token()
	if err != nil {
		return err
	}

	switch t := t.(type) {
	// single value
	case string:
		*s = append(*s, t)
		return nil
	// beginning of array
	case json.Delim:
		if t != '[' {
			return s.unmarshalError(r)
		}

	// unexpected token
	default:
		return s.unmarshalError(r)
	}

	for d.More() {
		t, err := d.Token()
		if err != nil {
			return err
		}

		if t, ok := t.(string); !ok {
			return s.unmarshalError(r)
		} else {
			*s = append(*s, t)
		}
	}

	t, err = d.Token()
	if err != nil {
		return err
	}

	// end of array
	if t, ok := t.(json.Delim); !ok || t != ']' {
		return s.unmarshalError(r)
	}

	return nil
}

func (s *StringOrArray) unmarshalError(r *bytes.Reader) error {
	return &json.UnmarshalTypeError{
		Value:  "string or array",
		Type:   reflect.TypeOf(s),
		Offset: r.Size() - int64(r.Len()),
	}
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

	return &json.UnmarshalTypeError{
		Value: "number",
		Type:  reflect.TypeOf(n),
	}
}

func (n NumericDate) Time() time.Time {
	return time.Unix(int64(n), 0)
}
