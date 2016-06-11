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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"crypto/x509"
)

func TestCurveSize(t *testing.T) {
	size256 := curveSize(elliptic.P256())
	size384 := curveSize(elliptic.P384())
	size521 := curveSize(elliptic.P521())
	if size256 != 32 {
		t.Error("P-256 have 32 bytes")
	}
	if size384 != 48 {
		t.Error("P-384 have 48 bytes")
	}
	if size521 != 66 {
		t.Error("P-521 have 66 bytes")
	}
}

func TestRoundtripRsaPrivate(t *testing.T) {
	jwk, err := fromRsaPrivateKey(rsaTestKey)
	if err != nil {
		t.Error("problem constructing JWK from rsa key", err)
	}

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

	_, err := fromRsaPrivateKey(&brokenRsaPrivateKey)
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

	_, err := fromRsaPrivateKey(&brokenRsaPrivateKey)
	if err != ErrUnsupportedKeyType {
		t.Error("expected unsupported key type error, got", err)
	}
}

func TestRoundtripEcPublic(t *testing.T) {
	for i, ecTestKey := range []*ecdsa.PrivateKey{ecTestKey256, ecTestKey384, ecTestKey521} {
		jwk, err := fromEcPublicKey(&ecTestKey.PublicKey)

		ec2, err := jwk.ecPublicKey()
		if err != nil {
			t.Error("problem converting ECDSA private -> JWK", i, err)
		}

		if !reflect.DeepEqual(ec2.Curve, ecTestKey.Curve) {
			t.Error("ECDSA private curve mismatch", i)
		}
		if ec2.X.Cmp(ecTestKey.X) != 0 {
			t.Error("ECDSA X mismatch", i)
		}
		if ec2.Y.Cmp(ecTestKey.Y) != 0 {
			t.Error("ECDSA Y mismatch", i)
		}
	}
}

func TestRoundtripEcPrivate(t *testing.T) {
	for i, ecTestKey := range []*ecdsa.PrivateKey{ecTestKey256, ecTestKey384, ecTestKey521} {
		jwk, err := fromEcPrivateKey(ecTestKey)

		ec2, err := jwk.ecPrivateKey()
		if err != nil {
			t.Error("problem converting ECDSA private -> JWK", i, err)
		}

		if !reflect.DeepEqual(ec2.Curve, ecTestKey.Curve) {
			t.Error("ECDSA private curve mismatch", i)
		}
		if ec2.X.Cmp(ecTestKey.X) != 0 {
			t.Error("ECDSA X mismatch", i)
		}
		if ec2.Y.Cmp(ecTestKey.Y) != 0 {
			t.Error("ECDSA Y mismatch", i)
		}
		if ec2.D.Cmp(ecTestKey.D) != 0 {
			t.Error("ECDSA D mismatch", i)
		}
	}
}

func TestMarshalUnmarshalX5C(t *testing.T) {
	jwk := JsonWebKey{
		Key: rsaTestKey,
		KeyID: "bar",
		Algorithm: "foo",
		Certificates: []*x509.Certificate{x509TestCertificate},
	}

	jsonbar, err := jwk.MarshalJSON()
	if err != nil {
		t.Error("problem marshaling", err)
	}

	t.Logf("JsonBAR: %s", jsonbar)

	var jwk2 JsonWebKey
	err = jwk2.UnmarshalJSON(jsonbar)
	if err != nil {
		t.Error("problem unmarshalling", err)
	}

	if !reflect.DeepEqual(jwk.Certificates, jwk2.Certificates) {
		t.Error("Certificates not equal", jwk.Certificates, jwk2.Certificates)
	}

	jsonbar2, err := jwk2.MarshalJSON()
	if err != nil {
		t.Error("problem marshaling", err)
	}
	if !bytes.Equal(jsonbar, jsonbar2) {
		t.Error("roundtrip should not lose information")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	kid := "DEADBEEF"

	for i, key := range []interface{}{ecTestKey256, ecTestKey384, ecTestKey521, rsaTestKey} {
		for _, use := range []string{"", "sig", "enc"} {
			jwk := JsonWebKey{Key: key, KeyID: kid, Algorithm: "foo"}
			if use != "" {
				jwk.Use = use
			}

			jsonbar, err := jwk.MarshalJSON()
			if err != nil {
				t.Error("problem marshaling", i, err)
			}

			var jwk2 JsonWebKey
			err = jwk2.UnmarshalJSON(jsonbar)
			if err != nil {
				t.Error("problem unmarshalling", i, err)
			}

			jsonbar2, err := jwk2.MarshalJSON()
			if err != nil {
				t.Error("problem marshaling", i, err)
			}

			if !bytes.Equal(jsonbar, jsonbar2) {
				t.Error("roundtrip should not lose information", i)
			}
			if jwk2.KeyID != kid {
				t.Error("kid did not roundtrip JSON marshalling", i)
			}

			if jwk2.Algorithm != "foo" {
				t.Error("alg did not roundtrip JSON marshalling", i)
			}

			if jwk2.Use != use {
				t.Error("use did not roundtrip JSON marshalling", i)
			}
		}
	}
}

func TestMarshalNonPointer(t *testing.T) {
	type EmbedsKey struct {
		Key JsonWebKey
	}

	keyJson := []byte(`{
		"e": "AQAB",
		"kty": "RSA",
		"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
	}`)
	var parsedKey JsonWebKey
	err := UnmarshalJSON(keyJson, &parsedKey)
	if err != nil {
		t.Error(fmt.Sprintf("Error unmarshalling key: %v", err))
		return
	}
	ek := EmbedsKey{
		Key: parsedKey,
	}
	out, err := MarshalJSON(ek)
	if err != nil {
		t.Error(fmt.Sprintf("Error marshalling JSON: %v", err))
		return
	}
	expected := "{\"Key\":{\"kty\":\"RSA\",\"n\":\"vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw\",\"e\":\"AQAB\"}}"
	if string(out) != expected {
		t.Error("Failed to marshal embedded non-pointer JWK properly:", string(out))
	}
}

func TestMarshalUnmarshalInvalid(t *testing.T) {
	// Make an invalid curve coordinate by creating a byte array that is one
	// byte too large, and setting the first byte to 1 (otherwise it's just zero).
	invalidCoord := make([]byte, curveSize(ecTestKey256.Curve)+1)
	invalidCoord[0] = 1

	keys := []interface{}{
		// Empty keys
		&rsa.PrivateKey{},
		&ecdsa.PrivateKey{},
		// Invalid keys
		&ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				// Missing values in pub key
				Curve: elliptic.P256(),
			},
		},
		&ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				// Invalid curve
				Curve: nil,
				X:     ecTestKey256.X,
				Y:     ecTestKey256.Y,
			},
		},
		&ecdsa.PrivateKey{
			// Valid pub key, but missing priv key values
			PublicKey: ecTestKey256.PublicKey,
		},
		&ecdsa.PrivateKey{
			// Invalid pub key, values too large
			PublicKey: ecdsa.PublicKey{
				Curve: ecTestKey256.Curve,
				X:     big.NewInt(0).SetBytes(invalidCoord),
				Y:     big.NewInt(0).SetBytes(invalidCoord),
			},
			D: ecTestKey256.D,
		},
		nil,
	}

	for i, key := range keys {
		jwk := JsonWebKey{Key: key}
		_, err := jwk.MarshalJSON()
		if err == nil {
			t.Error("managed to serialize invalid key", i)
		}
	}
}

func TestWebKeyVectorsInvalid(t *testing.T) {
	keys := []string{
		// Invalid JSON
		"{X",
		// Empty key
		"{}",
		// Invalid RSA keys
		`{"kty":"RSA"}`,
		`{"kty":"RSA","e":""}`,
		`{"kty":"RSA","e":"XXXX"}`,
		`{"kty":"RSA","d":"XXXX"}`,
		// Invalid EC keys
		`{"kty":"EC","crv":"ABC"}`,
		`{"kty":"EC","crv":"P-256"}`,
		`{"kty":"EC","crv":"P-256","d":"XXX"}`,
		`{"kty":"EC","crv":"ABC","d":"dGVzdA","x":"dGVzdA"}`,
		`{"kty":"EC","crv":"P-256","d":"dGVzdA","x":"dGVzdA"}`,
	}

	for _, key := range keys {
		var jwk2 JsonWebKey
		err := jwk2.UnmarshalJSON([]byte(key))
		if err == nil {
			t.Error("managed to parse invalid key:", key)
		}
	}
}

// Test vectors from RFC 7520
var cookbookJWKs = []string{
	// EC Public
	stripWhitespace(`{
     "kty": "EC",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
         A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
         SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`),

	// EC Private
	stripWhitespace(`{
     "kty": "EC",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
           A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
           SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
     "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb
           KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
   }`),

	// RSA Public
	stripWhitespace(`{
     "kty": "RSA",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
         -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
         wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
         oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
         3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
         LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
         HdrNP5zw",
     "e": "AQAB"
   }`),

	// RSA Private
	stripWhitespace(`{"kty":"RSA",
      "kid":"juliet@capulet.lit",
      "use":"enc",
      "n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy
           O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP
           8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0
           Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X
           OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1
           _I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q",
      "e":"AQAB",
      "d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS
           NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U
           vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu
           ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu
           rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a
           hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
      "p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf
           QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8
           UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws",
      "q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I
           edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK
           rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s",
      "dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3
           tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w
           Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c",
      "dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9
           GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy
           mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots",
      "qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq
           abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o
           Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"}`),

	// X.509 Certificate Chain
	stripWhitespace(`{"kty":"RSA",
      "use":"sig",
      "kid":"1b94c",
      "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08
           PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q
           u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a
           YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH
           MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv
           VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
      "e":"AQAB",
      "x5c":
           ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB
           gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD
           VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1
           wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg
           NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV
           QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w
           YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH
           YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66
           s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6
           SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn
           fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq
           PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk
           aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA
           QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL
           +9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1
           zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL
           2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo
           4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq
           gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]}`),
}

// SHA-256 thumbprints of the above keys, hex-encoded
var cookbookJWKThumbprints = []string{
	"747ae2dd2003664aeeb21e4753fe7402846170a16bc8df8f23a8cf06d3cbe793",
	"747ae2dd2003664aeeb21e4753fe7402846170a16bc8df8f23a8cf06d3cbe793",
	"f63838e96077ad1fc01c3f8405774dedc0641f558ebb4b40dccf5f9b6d66a932",
	"0fc478f8579325fcee0d4cbc6d9d1ce21730a6e97e435d6008fb379b0ebe47d4",
	"0ddb05bfedbec2070fa037324ba397396561d3425d6d69245570c261dc49dee3",
}

func TestWebKeyVectorsValid(t *testing.T) {
	for _, key := range cookbookJWKs {
		var jwk2 JsonWebKey
		err := jwk2.UnmarshalJSON([]byte(key))
		if err != nil {
			t.Error("unable to parse valid key:", key, err)
		}
	}
}

func TestThumbprint(t *testing.T) {
	for i, key := range cookbookJWKs {
		var jwk2 JsonWebKey
		err := jwk2.UnmarshalJSON([]byte(key))
		if err != nil {
			t.Error("unable to parse valid key:", key, err)
		}

		tp, err := jwk2.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Error("unable to compute thumbprint:", key, err)
		}

		tpHex := hex.EncodeToString(tp)
		if cookbookJWKThumbprints[i] != tpHex {
			t.Error("incorrect thumbprint:", i, cookbookJWKThumbprints[i], tpHex)
		}
	}
}

func TestMarshalUnmarshalJWKSet(t *testing.T) {
	jwk1 := JsonWebKey{Key: rsaTestKey, KeyID: "ABCDEFG", Algorithm: "foo"}
	jwk2 := JsonWebKey{Key: rsaTestKey, KeyID: "GFEDCBA", Algorithm: "foo"}
	var set JsonWebKeySet
	set.Keys = append(set.Keys, jwk1)
	set.Keys = append(set.Keys, jwk2)

	jsonbar, err := MarshalJSON(&set)
	if err != nil {
		t.Error("problem marshalling set", err)
	}
	var set2 JsonWebKeySet
	err = UnmarshalJSON(jsonbar, &set2)
	if err != nil {
		t.Error("problem unmarshalling set", err)
	}
	jsonbar2, err := MarshalJSON(&set2)
	if err != nil {
		t.Error("problem marshalling set", err)
	}
	if !bytes.Equal(jsonbar, jsonbar2) {
		t.Error("roundtrip should not lose information")
	}
}

func TestJWKSetKey(t *testing.T) {
	jwk1 := JsonWebKey{Key: rsaTestKey, KeyID: "ABCDEFG", Algorithm: "foo"}
	jwk2 := JsonWebKey{Key: rsaTestKey, KeyID: "GFEDCBA", Algorithm: "foo"}
	var set JsonWebKeySet
	set.Keys = append(set.Keys, jwk1)
	set.Keys = append(set.Keys, jwk2)
	k := set.Key("ABCDEFG")
	if len(k) != 1 {
		t.Errorf("method should return slice with one key not %d", len(k))
	}
	if k[0].KeyID != "ABCDEFG" {
		t.Error("method should return key with ID ABCDEFG")
	}
}

func TestJWKSymmetricKey(t *testing.T) {
	sample1 := `{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`
	sample2 := `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`

	var jwk1 JsonWebKey
	UnmarshalJSON([]byte(sample1), &jwk1)

	if jwk1.Algorithm != "A128KW" {
		t.Errorf("expected Algorithm to be A128KW, but was '%s'", jwk1.Algorithm)
	}
	expected1 := fromHexBytes("19ac2082e1721ab58a6afec05f854a52")
	if !bytes.Equal(jwk1.Key.([]byte), expected1) {
		t.Errorf("expected Key to be '%s', but was '%s'", hex.EncodeToString(expected1), hex.EncodeToString(jwk1.Key.([]byte)))
	}

	var jwk2 JsonWebKey
	UnmarshalJSON([]byte(sample2), &jwk2)

	if jwk2.KeyID != "HMAC key used in JWS spec Appendix A.1 example" {
		t.Errorf("expected KeyID to be 'HMAC key used in JWS spec Appendix A.1 example', but was '%s'", jwk2.KeyID)
	}
	expected2 := fromHexBytes(`
    0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebf
    d3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3`)
	if !bytes.Equal(jwk2.Key.([]byte), expected2) {
		t.Errorf("expected Key to be '%s', but was '%s'", hex.EncodeToString(expected2), hex.EncodeToString(jwk2.Key.([]byte)))
	}
}

func TestJWKSymmetricRoundtrip(t *testing.T) {
	jwk1 := JsonWebKey{Key: []byte{1, 2, 3, 4}}
	marshaled, err := jwk1.MarshalJSON()
	if err != nil {
		t.Errorf("failed to marshal valid JWK object", err)
	}

	var jwk2 JsonWebKey
	err = jwk2.UnmarshalJSON(marshaled)
	if err != nil {
		t.Errorf("failed to unmarshal valid JWK object", err)
	}

	if !bytes.Equal(jwk1.Key.([]byte), jwk2.Key.([]byte)) {
		t.Error("round-trip of symmetric JWK gave different raw keys")
	}
}

func TestJWKSymmetricInvalid(t *testing.T) {
	invalid := JsonWebKey{}
	_, err := invalid.MarshalJSON()
	if err == nil {
		t.Error("excepted error on marshaling invalid symmetric JWK object")
	}

	var jwk JsonWebKey
	err = jwk.UnmarshalJSON([]byte(`{"kty":"oct"}`))
	if err == nil {
		t.Error("excepted error on unmarshaling invalid symmetric JWK object")
	}
}

func TestJWKValid(t *testing.T) {
	bigInt := big.NewInt(0)
	eccPub := ecdsa.PublicKey{elliptic.P256(), bigInt, bigInt}
	rsaPub := rsa.PublicKey{bigInt, 1}
	cases := []struct {
		key              interface{}
		expectedValidity bool
	}{
		{nil, false},
		{&ecdsa.PublicKey{}, false},
		{&eccPub, true},
		{&ecdsa.PrivateKey{}, false},
		{&ecdsa.PrivateKey{eccPub, bigInt}, true},
		{&rsa.PublicKey{}, false},
		{&rsaPub, true},
		{&rsa.PrivateKey{}, false},
		{&rsa.PrivateKey{rsaPub, bigInt, []*big.Int{bigInt, bigInt}, rsa.PrecomputedValues{}}, true},
	}

	for _, tc := range cases {
		k := &JsonWebKey{Key: tc.key}
		if valid := k.Valid(); valid != tc.expectedValidity {
			t.Errorf("expected Valid to return %t, got %t", tc.expectedValidity, valid)
		}
	}
}
