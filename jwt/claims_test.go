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
	"bytes"
	"encoding/json"
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
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	r := strings.NewReader(s)
	d := json.NewDecoder(r)

	c := Claims{}
	if err := d.Decode(&c); err != nil {
		t.Error(err)
	}

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
