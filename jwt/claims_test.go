package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEncodeClaims(t *testing.T) {
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: []string{"a1", "a2"},
		IssuedAt: now,
		Expiry:   now.Add(1 * time.Hour),
	}

	b := &bytes.Buffer{}
	e := json.NewEncoder(b)

	if err := e.Encode(&c); err != nil {
		t.Error(err)
	}

	expected := `{"iss":"issuer","sub":"subject","aud":["a1","a2"],"exp":1451610000,"iat":1451606400}` + "\n"
	v := string(b.Bytes())
	if expected != v {
		t.Errorf("Expected encoded message to be %s, got %s", expected, v)
	}
}

func TestDecodeClaims(t *testing.T) {
	s := `{"iss":"issuer","sub":"subject","aud":["a1","a2"],"exp":1451610000,"iat":1451606400}` + "\n"
	d := json.NewDecoder(strings.NewReader(s))

	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{}
	if err := d.Decode(&c); err != nil {
		t.Error(err)
	}

	fmt.Println(c)

	if c.Issuer != "issuer" {
		t.Errorf("Invalid iss value")
	}

	if c.Subject != "subject" {
		t.Errorf("Invalid sub value")
	}

	if !reflect.DeepEqual([]string{"a1", "a2"}, c.Audience) {
		t.Errorf("Invalid aud value")
	}

	if !c.IssuedAt.Equal(now) {
		t.Errorf("Invalid iat value")
	}

	if !c.Expiry.Equal(now.Add(1 * time.Hour)) {
		t.Errorf("Invalid exp value")
	}
}
