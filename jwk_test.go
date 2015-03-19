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

package jose

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestParseInvalidKeys(t *testing.T) {
	invalids := []string{
		`{XXX`,
		`{"kty":[]}`,
		`{"kty":"EC","crv":"P-256","x":"###","y":""}`,
		`{"kty":"EC","crv":"P-256","x":"","y":"###"}`,
	}

	for _, invalid := range invalids {
		var jwk rawJsonWebKey
		err := json.Unmarshal([]byte(invalid), &jwk)
		if err == nil {
			t.Error("parser incorrectly parsed invalid key", jwk)
		}
	}
}

func TestParseInvalidECKeys(t *testing.T) {
	invalids := []string{
		`{"kty":"RSA"}`,
		`{"kty":"EC","crv":"XXX"}`,
		`{"kty":"EC","crv":"P-256","x":""}`,
	}

	for _, invalid := range invalids {
		var jwk rawJsonWebKey
		json.Unmarshal([]byte(invalid), &jwk)
		_, err := jwk.ecPublicKey()
		if err == nil {
			t.Error("ec parser incorrectly parsed invalid key", jwk)
		}
	}
}

func TestRoundtripRsaPrivate(t *testing.T) {
	var jwk rawJsonWebKey
	jwk.fromRsaPrivateKey(rsaTestKey)

	rsa2, err := jwk.rsaPrivateKey()
	if err != nil {
		t.Error("problem converting RSA private -> JWK", err)
	}

	if rsa2.N.Cmp(rsaTestKey.N) != 0 {
		t.Error("RSA private N mismatch")
	}
	if rsa2.E != rsaTestKey.E {
		t.Error("RSA private E mismatch")
	}
	if rsa2.D.Cmp(rsaTestKey.D) != 0 {
		t.Error("RSA private D mismatch")
	}
	if len(rsa2.Primes) != 2 {
		t.Error("RSA private roundtrip expected two primes")
	}
	if rsa2.Primes[0].Cmp(rsaTestKey.Primes[0]) != 0 {
		t.Error("RSA private P mismatch")
	}
	if rsa2.Primes[1].Cmp(rsaTestKey.Primes[1]) != 0 {
		t.Error("RSA private Q mismatch")
	}
}

func TestRsaPrivateInsufficientPrimes(t *testing.T) {
	brokenRsaPrivateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaTestKey.N,
			E: rsaTestKey.E,
		},
		D:      rsaTestKey.D,
		Primes: []*big.Int{rsaTestKey.Primes[0]},
	}
	var jwk rawJsonWebKey
	err := jwk.fromRsaPrivateKey(&brokenRsaPrivateKey)
	if err != ErrUnsupportedKeyType {
		t.Error("expected unsupported key type error, got", err)
	}
}

func TestRsaPrivateExcessPrimes(t *testing.T) {
	brokenRsaPrivateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaTestKey.N,
			E: rsaTestKey.E,
		},
		D: rsaTestKey.D,
		Primes: []*big.Int{
			rsaTestKey.Primes[0],
			rsaTestKey.Primes[1],
			big.NewInt(3),
		},
	}
	var jwk rawJsonWebKey
	err := jwk.fromRsaPrivateKey(&brokenRsaPrivateKey)
	if err != ErrUnsupportedKeyType {
		t.Error("expected unsupported key type error, got", err)
	}
}

func TestRoundtripEcPrivate(t *testing.T) {
	var jwk rawJsonWebKey
	jwk.fromEcPrivateKey(ecTestKey256)

	ec2, err := jwk.ecPrivateKey()
	if err != nil {
		t.Error("problem converting ECDSA private -> JWK", err)
	}

	if !reflect.DeepEqual(ec2.Curve, ecTestKey256.Curve) {
		t.Error("ECDSA private curve mismatch")
	}
	if ec2.X.Cmp(ecTestKey256.X) != 0 {
		t.Error("ECDSA X mismatch")
	}
	if ec2.Y.Cmp(ecTestKey256.Y) != 0 {
		t.Error("ECDSA Y mismatch")
	}
	if ec2.D.Cmp(ecTestKey256.D) != 0 {
		t.Error("ECDSA D mismatch")
	}
}

func TestKidMarshaling(t *testing.T) {
	kid := "DEADBEEF"

	jwk := JsonWebKey{key: ecTestKey256, kid: kid}
	jsonbar, err := jwk.MarshalJSON()
	if err != nil {
		t.Error("problem marshaling", err)
	}
	var jwk2 JsonWebKey
	err = jwk2.UnmarshalJSON(jsonbar)
	if err != nil {
		t.Error("problem unmarshalling", err)
	}

	if jwk2.kid != kid {
		t.Error("kid did not roundtrip JSON marshalling")
	}
}
