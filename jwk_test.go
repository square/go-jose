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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/square/go-jose/v3/json"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test chain of two X.509 certificates
var testCertificates, _ = x509.ParseCertificates(fromBase64Bytes(`
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`))

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

func TestRoundtripRsaPrivatePrecomputed(t *testing.T) {
	// Isolate a shallow copy of the rsaTestKey to avoid polluting it with Precompute
	localKey := &(*rsaTestKey)
	localKey.Precompute()

	jwk, err := fromRsaPrivateKey(localKey)
	if err != nil {
		t.Error("problem constructing JWK from rsa key", err)
	}

	rsa2, err := jwk.rsaPrivateKey()
	if err != nil {
		t.Error("problem converting RSA private -> JWK", err)
	}

	if rsa2.Precomputed.Dp == nil {
		t.Error("RSA private Dp nil")
	}
	if rsa2.Precomputed.Dq == nil {
		t.Error("RSA private Dq nil")
	}
	if rsa2.Precomputed.Qinv == nil {
		t.Error("RSA private Qinv nil")
	}

	if rsa2.Precomputed.Dp.Cmp(localKey.Precomputed.Dp) != 0 {
		t.Error("RSA private Dp mismatch")
	}
	if rsa2.Precomputed.Dq.Cmp(localKey.Precomputed.Dq) != 0 {
		t.Error("RSA private Dq mismatch")
	}
	if rsa2.Precomputed.Qinv.Cmp(localKey.Precomputed.Qinv) != 0 {
		t.Error("RSA private Qinv mismatch")
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
		if err != nil {
			t.Fatal(err)
		}

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
		if err != nil {
			t.Fatal(err)
		}

		ec2, err := jwk.ecPrivateKey()
		if err != nil {
			t.Fatalf("problem converting ECDSA private -> JWK for %#v: %s", ecTestKey, err)
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

func TestRoundtripX509(t *testing.T) {
	x5tSHA1 := sha1.Sum(testCertificates[0].Raw)
	x5tSHA256 := sha256.Sum256(testCertificates[0].Raw)

	cases := []struct {
		name string
		jwk  JSONWebKey
	}{
		{
			name: "all fields",
			jwk: JSONWebKey{
				Key:                         testCertificates[0].PublicKey,
				KeyID:                       "bar",
				Algorithm:                   "foo",
				Certificates:                testCertificates,
				CertificateThumbprintSHA1:   x5tSHA1[:],
				CertificateThumbprintSHA256: x5tSHA256[:],
			},
		},
		{
			name: "no optional x5ts",
			jwk: JSONWebKey{
				Key:          testCertificates[0].PublicKey,
				KeyID:        "bar",
				Algorithm:    "foo",
				Certificates: testCertificates,
			},
		},
		{
			name: "no x5t",
			jwk: JSONWebKey{
				Key:                         testCertificates[0].PublicKey,
				KeyID:                       "bar",
				Algorithm:                   "foo",
				Certificates:                testCertificates,
				CertificateThumbprintSHA256: x5tSHA256[:],
			},
		},
		{
			name: "no x5t#S256",
			jwk: JSONWebKey{
				Key:                       testCertificates[0].PublicKey,
				KeyID:                     "bar",
				Algorithm:                 "foo",
				Certificates:              testCertificates,
				CertificateThumbprintSHA1: x5tSHA1[:],
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			jsonbar, err := c.jwk.MarshalJSON()
			require.NoError(t, err)

			var jwk2 JSONWebKey
			err = jwk2.UnmarshalJSON(jsonbar)
			require.NoError(t, err)

			if !reflect.DeepEqual(testCertificates, jwk2.Certificates) {
				t.Error("Certificates not equal", c.jwk.Certificates, jwk2.Certificates)
			}

			jsonbar2, err := jwk2.MarshalJSON()
			require.NoError(t, err)

			require.Empty(t, cmp.Diff(jsonbar, jsonbar2))
			if !bytes.Equal(jsonbar, jsonbar2) {
				t.Error("roundtrip should not lose information")
			}
		})
	}
}

func TestRoundtripX509Hex(t *testing.T) {
	var hexJWK = `{
   "kty":"RSA",
   "kid":"bar",
   "alg":"foo",
   "n":"u7LUr30Mhrh8N79-H4rKiHQ123q6xaBZPYbf1nV4GM19rizSnbEfyebG1kpfCv-XY6c499XiM6lOvcPL-0goTOcfW6Lg7AAR895GbnMeXEmnxICaI8rAZHK6t1WPmiWp82y_qhK2F_pYUaT3GSuiTFiMGq_GNwdpWuMlsInnnMNv1nxFbxtDPwzmCp0fEBxbH5d1EtXZwTPOHMyj8rfa-NIA5Nl4h_5RrbOWveKwBr26_CDAratJgOWh9xcd5g0ot_uDGcMoAgB6xeTuYklfaxCPptvu49kvoxw1J71fp6nKW_ZuhDRAp2F_BQ9inKpTo05sPLJg8tPTdjaeouOuJQ",
   "e":"AQAB",
   "x5c":[
      "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"
	],
	"x5t": "MDYxMjU0ZmRmNzIwZjJjMGU0YmQzZjMzMzlhMmZlNTM1MGExNWRlMQ",
	"x5t#S256": "MjAzMjRhNGI5MmYxMjI2OGVmOWFlMDI1ZmQ1Yzc5ZDE1OGZmNzQ1NzQwMDkyMTk2ZTgzNTNjMDAzMTUxNzUxMQ"
}`

	// json output
	var output = `{
	"kty":"RSA",
	"kid":"bar",
	"alg":"foo",
	"n":"u7LUr30Mhrh8N79-H4rKiHQ123q6xaBZPYbf1nV4GM19rizSnbEfyebG1kpfCv-XY6c499XiM6lOvcPL-0goTOcfW6Lg7AAR895GbnMeXEmnxICaI8rAZHK6t1WPmiWp82y_qhK2F_pYUaT3GSuiTFiMGq_GNwdpWuMlsInnnMNv1nxFbxtDPwzmCp0fEBxbH5d1EtXZwTPOHMyj8rfa-NIA5Nl4h_5RrbOWveKwBr26_CDAratJgOWh9xcd5g0ot_uDGcMoAgB6xeTuYklfaxCPptvu49kvoxw1J71fp6nKW_ZuhDRAp2F_BQ9inKpTo05sPLJg8tPTdjaeouOuJQ",
	"e":"AQAB",
	"x5c":[
		"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"
	],
	"x5t":"BhJU_fcg8sDkvT8zOaL-U1ChXeE",
	"x5t#S256":"IDJKS5LxImjvmuAl_Vx50Vj_dFdACSGW6DU8ADFRdRE"
	}`

	var jwk2 JSONWebKey
	err := jwk2.UnmarshalJSON([]byte(hexJWK))
	require.NoError(t, err)

	js, err := jwk2.MarshalJSON()
	require.NoError(t, err)

	var j1, j2 map[string]interface{}
	require.NoError(t, json.Unmarshal(js, &j1))
	require.NoError(t, json.Unmarshal([]byte(output), &j2))
	require.Empty(t, cmp.Diff(j1, j2))
}

func TestInvalidThumbprintsX509(t *testing.T) {
	// Too short
	jwk := JSONWebKey{
		Key:                         rsaTestKey,
		KeyID:                       "bar",
		Algorithm:                   "foo",
		Certificates:                testCertificates,
		CertificateThumbprintSHA1:   []byte{0x01}, // invalid length
		CertificateThumbprintSHA256: []byte{0x02}, // invalid length
	}

	_, err := jwk.MarshalJSON()
	if err == nil {
		t.Error("should not marshal JWK with too short thumbprints")
	}

	// Mismatched (leaf has different sum)
	sha1sum := sha1.Sum(nil)
	jwk.CertificateThumbprintSHA1 = sha1sum[:]
	sha256sum := sha256.Sum256(nil)
	jwk.CertificateThumbprintSHA256 = sha256sum[:]

	_, err = jwk.MarshalJSON()
	if err == nil {
		t.Error("should not marshal JWK with mismatched thumbprints")
	}

	// Too short
	shortThumbprints := []byte(`{
  "kty": "RSA",
  "kid": "bar",
  "alg": "foo",
  "n": "wN3v274Fr7grvZdXirEGkHlhYKh72gP-46MxQilMgANi6EaX2m0mYiMC60X1UmOhQNoVW0ItthMME-CGh7haA_Jeou_L6-EVOz-7lGu_J06VRl-mgkQZO0sYSkRY8Rsu7TW-pgnWWwZjSdgxN2gq7DvjjC4RLroV94Lgrb2Qwx6J5bZNOfj3pHmEWZ_eRFEH73Ct5RxwUKtNKx_XAmodZn9oFXBlN7F2Js-4DO-8UgbS7ALkTmhDzClT1GPfdLMusmXw4BXyV72vBOWrbUTdwk4pG8ahPQ0cGQ1ubaAmro_k3Bxg06voWPhXx7ALrpzmZCzr6YY-c5Y5rku4qXh-HQ",
  "e": "AQAB",
  "d": "RRM3xMvZ3YVopQ5_G_0rDLNsXOH6-apUr9LS4Y9JBtAvrGEcIe7VwHApq3ny0v870a5J19Vr6boIqVXQ2Or90kwL-O9JacHDiOTamd29KKbMb9fyGtWo88OBf5fbAv9pXyvQjEcZrqArD1eOyPlV5iXM6XfWT5X2KB-HuLIcFsVJSEb0yw943dEhZKkv2fySlVtKEhji2CfkMWP438G8auxwFPNIXmuvA1xvcAepOiI9I1Wy17txLOQg8MYBl98F7mxPUMpL3jm8-CSuxpknucFuFIrqIsbGmukSNp14APcu7bN0cJW5uVW-XtGbuioJkPjU2YJgfhIeMI8kuny5QQ",
  "p": "yRNzbsreZK9MqJgbVsbl7SX2MyyJW_JnFKGdyrXzMqCtzRS7XJ9L3SwdDG_ERgSCkT9PP2dax9fS7RghHNJIU_NlPnJqzBPvPyzbjho7hcGYGDU2UO8E3SBP1WKm1SnlYhm1uHwrHudAO0D5jhVYQfRwem-zX3QibrsxEyxSELM",
  "q": "9Yx0zzrhSxdE8ubryZfOyOw6cSbUdyCMgY3IFmEdb_UDZOQNMDCFj2RS1g6yFGKuaFqnL9ZRnmprikf20w-mu-LtLU_l0eK4U7pbAoB--pxFP_O6Yk3ZBu_YJ3FpimyX1v4OVZT-JOU_caKiTrPnlw3P7KbEc9iu_bOc8dE-_e8",
  "dp": "GwiFbXDS44B58vS4QDtvcCm5Zvnm4bi-SRTNbRJ3Rug5Vagi5Hn6LhsfMKvaHHvAvhxf4CtaFiIbFos28HQJC1he1T12xEct1DWIsxstw3bapu6IhesMoVoVwZ-IxIHkeALy3oG7HmWCyjSbGJIgEoX1lVBtMjkf4_lAyM4dnmc",
  "dq": "XYtXyMbOo3PG8Z6lfxRVU9gi346CbKu6u3RPIK94rnkyBNKYb55ck2cN47yPfRKnDNxUSvYj--zg8To_PuL8iyGFZ7jDffUYcdVR7J8VQNYdz6JDhEXSA0GGIGilY3XBVsdMoK_1Lgsj41-o48DH3pUFfEuAFf4blE1D4h_sFoM",
  "qi": "CN3q5TMZO06DlK4onrJ687bPp2GE-fynd7ADPdf1ek3cXbeaFApVNp4w-i8zr7IVugQohn01i_jnkymw4UN-acoIzX2sGYhgDm6le1jyfv28bQ_Z5hT0rFNlPfGyK0kkPYUTxZ4ZCKpCYJT9C1nH58Yu4xFk4VR1zhULegjCCd4",
  "x5c": [
    "MIIDfDCCAmSgAwIBAgIJANWAkzF7PA8/MA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEChMHY2VydGlnbzEQMA4GA1UECxMHZXhhbXBsZTEVMBMGA1UEAxMMZXhhbXBsZS1sZWFmMB4XDTE2MDYxMDIyMTQxMVoXDTIzMDQxNTIyMTQxMVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLWxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7stSvfQyGuHw3v34fisqIdDXberrFoFk9ht/WdXgYzX2uLNKdsR/J5sbWSl8K/5djpzj31eIzqU69w8v7SChM5x9bouDsABHz3kZucx5cSafEgJojysBkcrq3VY+aJanzbL+qErYX+lhRpPcZK6JMWIwar8Y3B2la4yWwieecw2/WfEVvG0M/DOYKnR8QHFsfl3US1dnBM84czKPyt9r40gDk2XiH/lGts5a94rAGvbr8IMCtq0mA5aH3Fx3mDSi3+4MZwygCAHrF5O5iSV9rEI+m2+7j2S+jHDUnvV+nqcpb9m6ENECnYX8FD2KcqlOjTmw8smDy09N2Np6i464lAgMBAAGjTzBNMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAsBgNVHREEJTAjhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAGM4aa/qrURUweZBIwZYv8O9b2+r4l0HjGAh982/B9sMlM05kojyDCUGvj86z18Lm8mKr4/y+i0nJ+vDIksEvfDuzw5ALAXGcBzPJKtICUf7LstA/n9NNpshWz0kld9ylnB5mbUzSFDncVyeXkEf5sGQXdIIZT9ChRBoiloSaa7dvBVCcsX1LGP2LWqKtD+7nUnw5qCwtyAVT8pthEUxFTpywoiJS5ZdzeEx8MNGvUeLFj2kleqPF78EioEQlSOxViCuctEtnQuPcDLHNFr10byTZY9roObiqdsJLMVvb2XliJjAqaPa9AkYwGE6xHw2ispwg64Rse0+AtKups19WIU="
  ],
  "x5t": "BhJU_fcg8sDkvT8zOaL-U1C",
  "x5t#S256": "IDJKS5LxImjvmuAl_Vx50Vj_dFdACSGW6DU8ADF"
}`)

	// Mismatched (leaf has different sum)
	mismatchedThumbprints := []byte(`{
  "kty": "RSA",
  "kid": "bar",
  "alg": "foo",
  "n": "wN3v274Fr7grvZdXirEGkHlhYKh72gP-46MxQilMgANi6EaX2m0mYiMC60X1UmOhQNoVW0ItthMME-CGh7haA_Jeou_L6-EVOz-7lGu_J06VRl-mgkQZO0sYSkRY8Rsu7TW-pgnWWwZjSdgxN2gq7DvjjC4RLroV94Lgrb2Qwx6J5bZNOfj3pHmEWZ_eRFEH73Ct5RxwUKtNKx_XAmodZn9oFXBlN7F2Js-4DO-8UgbS7ALkTmhDzClT1GPfdLMusmXw4BXyV72vBOWrbUTdwk4pG8ahPQ0cGQ1ubaAmro_k3Bxg06voWPhXx7ALrpzmZCzr6YY-c5Y5rku4qXh-HQ",
  "e": "AQAB",
  "d": "RRM3xMvZ3YVopQ5_G_0rDLNsXOH6-apUr9LS4Y9JBtAvrGEcIe7VwHApq3ny0v870a5J19Vr6boIqVXQ2Or90kwL-O9JacHDiOTamd29KKbMb9fyGtWo88OBf5fbAv9pXyvQjEcZrqArD1eOyPlV5iXM6XfWT5X2KB-HuLIcFsVJSEb0yw943dEhZKkv2fySlVtKEhji2CfkMWP438G8auxwFPNIXmuvA1xvcAepOiI9I1Wy17txLOQg8MYBl98F7mxPUMpL3jm8-CSuxpknucFuFIrqIsbGmukSNp14APcu7bN0cJW5uVW-XtGbuioJkPjU2YJgfhIeMI8kuny5QQ",
  "p": "yRNzbsreZK9MqJgbVsbl7SX2MyyJW_JnFKGdyrXzMqCtzRS7XJ9L3SwdDG_ERgSCkT9PP2dax9fS7RghHNJIU_NlPnJqzBPvPyzbjho7hcGYGDU2UO8E3SBP1WKm1SnlYhm1uHwrHudAO0D5jhVYQfRwem-zX3QibrsxEyxSELM",
  "q": "9Yx0zzrhSxdE8ubryZfOyOw6cSbUdyCMgY3IFmEdb_UDZOQNMDCFj2RS1g6yFGKuaFqnL9ZRnmprikf20w-mu-LtLU_l0eK4U7pbAoB--pxFP_O6Yk3ZBu_YJ3FpimyX1v4OVZT-JOU_caKiTrPnlw3P7KbEc9iu_bOc8dE-_e8",
  "dp": "GwiFbXDS44B58vS4QDtvcCm5Zvnm4bi-SRTNbRJ3Rug5Vagi5Hn6LhsfMKvaHHvAvhxf4CtaFiIbFos28HQJC1he1T12xEct1DWIsxstw3bapu6IhesMoVoVwZ-IxIHkeALy3oG7HmWCyjSbGJIgEoX1lVBtMjkf4_lAyM4dnmc",
  "dq": "XYtXyMbOo3PG8Z6lfxRVU9gi346CbKu6u3RPIK94rnkyBNKYb55ck2cN47yPfRKnDNxUSvYj--zg8To_PuL8iyGFZ7jDffUYcdVR7J8VQNYdz6JDhEXSA0GGIGilY3XBVsdMoK_1Lgsj41-o48DH3pUFfEuAFf4blE1D4h_sFoM",
  "qi": "CN3q5TMZO06DlK4onrJ687bPp2GE-fynd7ADPdf1ek3cXbeaFApVNp4w-i8zr7IVugQohn01i_jnkymw4UN-acoIzX2sGYhgDm6le1jyfv28bQ_Z5hT0rFNlPfGyK0kkPYUTxZ4ZCKpCYJT9C1nH58Yu4xFk4VR1zhULegjCCd4",
  "x5c": [
    "MIIDfDCCAmSgAwIBAgIJANWAkzF7PA8/MA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEChMHY2VydGlnbzEQMA4GA1UECxMHZXhhbXBsZTEVMBMGA1UEAxMMZXhhbXBsZS1sZWFmMB4XDTE2MDYxMDIyMTQxMVoXDTIzMDQxNTIyMTQxMVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLWxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7stSvfQyGuHw3v34fisqIdDXberrFoFk9ht/WdXgYzX2uLNKdsR/J5sbWSl8K/5djpzj31eIzqU69w8v7SChM5x9bouDsABHz3kZucx5cSafEgJojysBkcrq3VY+aJanzbL+qErYX+lhRpPcZK6JMWIwar8Y3B2la4yWwieecw2/WfEVvG0M/DOYKnR8QHFsfl3US1dnBM84czKPyt9r40gDk2XiH/lGts5a94rAGvbr8IMCtq0mA5aH3Fx3mDSi3+4MZwygCAHrF5O5iSV9rEI+m2+7j2S+jHDUnvV+nqcpb9m6ENECnYX8FD2KcqlOjTmw8smDy09N2Np6i464lAgMBAAGjTzBNMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAsBgNVHREEJTAjhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAGM4aa/qrURUweZBIwZYv8O9b2+r4l0HjGAh982/B9sMlM05kojyDCUGvj86z18Lm8mKr4/y+i0nJ+vDIksEvfDuzw5ALAXGcBzPJKtICUf7LstA/n9NNpshWz0kld9ylnB5mbUzSFDncVyeXkEf5sGQXdIIZT9ChRBoiloSaa7dvBVCcsX1LGP2LWqKtD+7nUnw5qCwtyAVT8pthEUxFTpywoiJS5ZdzeEx8MNGvUeLFj2kleqPF78EioEQlSOxViCuctEtnQuPcDLHNFr10byTZY9roObiqdsJLMVvb2XliJjAqaPa9AkYwGE6xHw2ispwg64Rse0+AtKups19WIU="
  ],
  "x5t": "BhJU_fcg8sDkvT8zOaL-U1ChXeX",
  "x5t#S256": "IDJKS5LxImjvmuAl_Vx50Vj_dFdACSGW6DU8ADFRdRX"
}`)

	var jwk2 JSONWebKey
	err = jwk2.UnmarshalJSON(mismatchedThumbprints)
	if err == nil {
		t.Error("should not unmarshal JWK with mismatched thumbprints")
	}

	err = jwk2.UnmarshalJSON(shortThumbprints)
	if err == nil {
		t.Error("should not unmarshal JWK with too short thumbprints")
	}
}

func TestKeyMismatchX509(t *testing.T) {
	x5tSHA1 := sha1.Sum(testCertificates[0].Raw)
	x5tSHA256 := sha256.Sum256(testCertificates[0].Raw)

	jwk := JSONWebKey{
		KeyID:                       "bar",
		Algorithm:                   "foo",
		Certificates:                testCertificates,
		CertificateThumbprintSHA1:   x5tSHA1[:],
		CertificateThumbprintSHA256: x5tSHA256[:],
	}

	for _, key := range []interface{}{
		// None of these keys should match what's in the cert, so parsing should always fail.
		ecTestKey256,
		ecTestKey256.Public(),
		ecTestKey384,
		ecTestKey384.Public(),
		ecTestKey521,
		ecTestKey521.Public(),
		rsaTestKey,
		rsaTestKey.Public(),
		ed25519PrivateKey,
		ed25519PrivateKey.Public(),
	} {
		jwk.Key = key
		raw, _ := jwk.MarshalJSON()

		var jwk2 JSONWebKey
		err := jwk2.UnmarshalJSON(raw)
		if err == nil {
			t.Error("should not unmarshal JWK with key/cert mismatch")
		}
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	kid := "DEADBEEF"

	for i, key := range []interface{}{
		ecTestKey256,
		ecTestKey256.Public(),
		ecTestKey384,
		ecTestKey384.Public(),
		ecTestKey521,
		ecTestKey521.Public(),
		rsaTestKey,
		rsaTestKey.Public(),
		ed25519PrivateKey,
		ed25519PrivateKey.Public(),
	} {
		for _, use := range []string{"", "sig", "enc"} {
			jwk := JSONWebKey{Key: key, KeyID: kid, Algorithm: "foo"}
			if use != "" {
				jwk.Use = use
			}

			jsonbar, err := jwk.MarshalJSON()
			if err != nil {
				t.Error("problem marshaling", i, err)
			}

			var jwk2 JSONWebKey
			err = jwk2.UnmarshalJSON(jsonbar)
			if err != nil {
				t.Fatal("problem unmarshalling", i, err)
			}

			jsonbar2, err := jwk2.MarshalJSON()
			if err != nil {
				t.Fatal("problem marshaling", i, err)
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
		Key JSONWebKey
	}

	keyJSON := []byte(`{
		"e": "AQAB",
		"kty": "RSA",
		"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
	}`)
	var parsedKey JSONWebKey
	err := json.Unmarshal(keyJSON, &parsedKey)
	if err != nil {
		t.Errorf("Error unmarshalling key: %v", err)
		return
	}
	ek := EmbedsKey{
		Key: parsedKey,
	}
	out, err := json.Marshal(ek)
	if err != nil {
		t.Errorf("Error marshalling JSON: %v", err)
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
		jwk := JSONWebKey{Key: key}
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
		var jwk2 JSONWebKey
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

	//ED Private
	stripWhitespace(`{
     "kty": "OKP",
     "crv": "Ed25519",
     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
     "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
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
	"f6934029a341ddf81dceb753e91d17efe16664f40d9f4ed84bc5ea87e111f29d",
	"747ae2dd2003664aeeb21e4753fe7402846170a16bc8df8f23a8cf06d3cbe793",
	"f63838e96077ad1fc01c3f8405774dedc0641f558ebb4b40dccf5f9b6d66a932",
	"0fc478f8579325fcee0d4cbc6d9d1ce21730a6e97e435d6008fb379b0ebe47d4",
	"0ddb05bfedbec2070fa037324ba397396561d3425d6d69245570c261dc49dee3",
}

func TestWebKeyVectorsValid(t *testing.T) {
	for _, key := range cookbookJWKs {
		var jwk2 JSONWebKey
		err := jwk2.UnmarshalJSON([]byte(key))
		if err != nil {
			t.Error("unable to parse valid key:", key, err)
		}
	}
}

func TestEd25519Serialization(t *testing.T) {
	jwk := JSONWebKey{
		Key: ed25519PrivateKey,
	}
	serialized, _ := json.Marshal(jwk)

	var jwk2 JSONWebKey
	if err := json.Unmarshal(serialized, &jwk2); err != nil {
		t.Fatal(err)
	}

	assert.True(t, bytes.Equal(
		[]byte(jwk.Key.(ed25519.PrivateKey).Public().(ed25519.PublicKey)),
		[]byte(jwk2.Key.(ed25519.PrivateKey).Public().(ed25519.PublicKey))))
}

func TestThumbprint(t *testing.T) {
	for i, key := range cookbookJWKs {
		var jwk2 JSONWebKey
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
	jwk1 := JSONWebKey{Key: rsaTestKey, KeyID: "ABCDEFG", Algorithm: "foo"}
	jwk2 := JSONWebKey{Key: rsaTestKey, KeyID: "GFEDCBA", Algorithm: "foo"}
	var set JSONWebKeySet
	set.Keys = append(set.Keys, jwk1)
	set.Keys = append(set.Keys, jwk2)

	jsonbar, err := json.Marshal(&set)
	if err != nil {
		t.Error("problem marshalling set", err)
	}
	var set2 JSONWebKeySet
	err = json.Unmarshal(jsonbar, &set2)
	if err != nil {
		t.Fatal("problem unmarshalling set", err)
	}
	jsonbar2, err := json.Marshal(&set2)
	if err != nil {
		t.Fatal("problem marshalling set", err)
	}
	if !bytes.Equal(jsonbar, jsonbar2) {
		t.Error("roundtrip should not lose information")
	}
}

func TestJWKSetKey(t *testing.T) {
	jwk1 := JSONWebKey{Key: rsaTestKey, KeyID: "ABCDEFG", Algorithm: "foo"}
	jwk2 := JSONWebKey{Key: rsaTestKey, KeyID: "GFEDCBA", Algorithm: "foo"}
	var set JSONWebKeySet
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

	var jwk1 JSONWebKey
	if err := json.Unmarshal([]byte(sample1), &jwk1); err != nil {
		t.Fatal(err)
	}

	if jwk1.Algorithm != "A128KW" {
		t.Errorf("expected Algorithm to be A128KW, but was '%s'", jwk1.Algorithm)
	}
	expected1 := fromHexBytes("19ac2082e1721ab58a6afec05f854a52")
	if !bytes.Equal(jwk1.Key.([]byte), expected1) {
		t.Errorf("expected Key to be '%s', but was '%s'", hex.EncodeToString(expected1), hex.EncodeToString(jwk1.Key.([]byte)))
	}

	var jwk2 JSONWebKey
	if err := json.Unmarshal([]byte(sample2), &jwk2); err != nil {
		t.Fatal(err)
	}

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
	jwk1 := JSONWebKey{Key: []byte{1, 2, 3, 4}}
	marshaled, err := jwk1.MarshalJSON()
	if err != nil {
		t.Error("failed to marshal valid JWK object", err)
	}

	var jwk2 JSONWebKey
	err = jwk2.UnmarshalJSON(marshaled)
	if err != nil {
		t.Error("failed to unmarshal valid JWK object", err)
	}

	if !bytes.Equal(jwk1.Key.([]byte), jwk2.Key.([]byte)) {
		t.Error("round-trip of symmetric JWK gave different raw keys")
	}
}

func TestJWKSymmetricInvalid(t *testing.T) {
	invalid := JSONWebKey{}
	_, err := invalid.MarshalJSON()
	if err == nil {
		t.Error("excepted error on marshaling invalid symmetric JWK object")
	}

	var jwk JSONWebKey
	err = jwk.UnmarshalJSON([]byte(`{"kty":"oct"}`))
	if err == nil {
		t.Error("excepted error on unmarshaling invalid symmetric JWK object")
	}
}

func TestJWKIsPublic(t *testing.T) {
	bigInt := big.NewInt(0)
	eccPub := ecdsa.PublicKey{Curve: elliptic.P256(), X: bigInt, Y: bigInt}
	rsaPub := rsa.PublicKey{N: bigInt, E: 1}

	cases := []struct {
		key              interface{}
		expectedIsPublic bool
	}{
		{&eccPub, true},
		{&ecdsa.PrivateKey{PublicKey: eccPub, D: bigInt}, false},
		{&rsaPub, true},
		{&rsa.PrivateKey{PublicKey: rsaPub, D: bigInt, Primes: []*big.Int{bigInt, bigInt}}, false},
		{ed25519PublicKey, true},
		{ed25519PrivateKey, false},
	}

	for _, tc := range cases {
		k := &JSONWebKey{Key: tc.key}
		if public := k.IsPublic(); public != tc.expectedIsPublic {
			t.Errorf("expected IsPublic to return %t, got %t", tc.expectedIsPublic, public)
		}
	}
}

func TestJWKValid(t *testing.T) {
	bigInt := big.NewInt(0)
	eccPub := ecdsa.PublicKey{Curve: elliptic.P256(), X: bigInt, Y: bigInt}
	rsaPub := rsa.PublicKey{N: bigInt, E: 1}
	edPubEmpty := ed25519.PublicKey([]byte{})
	edPrivEmpty := ed25519.PublicKey([]byte{})

	cases := []struct {
		key              interface{}
		expectedValidity bool
	}{
		{nil, false},
		{&ecdsa.PublicKey{}, false},
		{&eccPub, true},
		{&ecdsa.PrivateKey{}, false},
		{&ecdsa.PrivateKey{PublicKey: eccPub, D: bigInt}, true},
		{&rsa.PublicKey{}, false},
		{&rsaPub, true},
		{&rsa.PrivateKey{}, false},
		{&rsa.PrivateKey{PublicKey: rsaPub, D: bigInt, Primes: []*big.Int{bigInt, bigInt}}, true},
		{ed25519PublicKey, true},
		{ed25519PrivateKey, true},
		{edPubEmpty, false},
		{edPrivEmpty, false},
	}

	for _, tc := range cases {
		k := &JSONWebKey{Key: tc.key}
		valid := k.Valid()
		if valid != tc.expectedValidity {
			t.Errorf("expected Valid to return %t, got %t", tc.expectedValidity, valid)
		}
		if valid {
			wasPublic := k.IsPublic()
			p := k.Public() // all aforemention keys are asymmetric
			if !p.Valid() {
				t.Errorf("unable to derive public key from valid asymmetric key")
			}
			if wasPublic != k.IsPublic() {
				t.Errorf("original key was touched during public key derivation")
			}
		}
	}
}

func TestJWKBufferSizeCheck(t *testing.T) {
	key := `{
		"kty":"EC",
		"crv":"P-256",
		"x":"m9GSmJ5iGmAYlMlaOJGSFN_CjN9cIn8GGYExP-C0FBiIXlWTNvGN38R9WdrHcppfsKF0FXMOMyutpHIRaiMxYSA",
		"y":"ZaPcRZ3q_7T3h-Gwz2i-T2JjJXfj6YVGgKHcFz5zqmg"}`
	var jwk JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(key)); err == nil {
		t.Fatal("key should be invalid")
	}
	jwk.Valid() // true
	// panic: square/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)
	// github.com/square/go-jose.newFixedSizeBuffer(0xc420014557, 0x41, 0x41, 0x20, 0x0)
	jwk.Thumbprint(crypto.SHA256)
}

func TestJWKPaddingPrivateX(t *testing.T) {
	key := `{
    "kty": "EC",
    "crv": "P-256",
    "x": "nPTIABcDASY6FNGSNfHCB51tY7qChtgzeVazOtLrwQ",
    "y": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs",
    "d": "nIVCvMR2wkLmeGJErOpI23VDHl2s3JwGdbzKy0odir0"
  }`
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(key))
	if err == nil {
		t.Errorf("Expected key with short x to fail unmarshalling")
	}
	if !strings.Contains(err.Error(), "wrong length for x") {
		t.Errorf("Wrong error for short x, got %q", err)
	}
	if jwk.Valid() {
		t.Errorf("Expected key to be invalid, but it was valid.")
	}
}

func TestJWKPaddingPrivateY(t *testing.T) {
	key := `{
    "kty": "EC",
    "crv": "P-256",
    "x": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs",
    "y": "nPTIABcDASY6FNGSNfHCB51tY7qChtgzeVazOtLrwQ",
    "d": "nIVCvMR2wkLmeGJErOpI23VDHl2s3JwGdbzKy0odir0"
  }`
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(key))
	if err == nil {
		t.Errorf("Expected key with short x to fail unmarshalling")
	}
	if !strings.Contains(err.Error(), "wrong length for y") {
		t.Errorf("Wrong error for short y, got %q", err)
	}
	if jwk.Valid() {
		t.Errorf("Expected key to be invalid, but it was valid.")
	}
}

func TestJWKPaddingPrivateD(t *testing.T) {
	key := `{
    "kty": "EC",
    "crv": "P-256",
    "x": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs",
    "y": "qnPTIABcDASY6FNGSNfHCB51tY7qChtgzeVazOtLrwQ",
    "d": "IVCvMR2wkLmeGJErOpI23VDHl2s3JwGdbzKy0odir0"
  }`
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(key))
	if err == nil {
		t.Errorf("Expected key with short x to fail unmarshalling")
	}
	if !strings.Contains(err.Error(), "wrong length for d") {
		t.Errorf("Wrong error for short d, got %q", err)
	}
	if jwk.Valid() {
		t.Errorf("Expected key to be invalid, but it was valid.")
	}
}

func TestJWKPaddingX(t *testing.T) {
	key := `{
    "kty": "EC",
    "crv": "P-256",
    "x": "nPTIABcDASY6FNGSNfHCB51tY7qChtgzeVazOtLrwQ",
    "y": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs"
  }`
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(key))
	if err == nil {
		t.Errorf("Expected key with short x to fail unmarshalling")
	}
	if !strings.Contains(err.Error(), "wrong length for x") {
		t.Errorf("Wrong error for short x, got %q", err)
	}
	if jwk.Valid() {
		t.Errorf("Expected key to be invalid, but it was valid.")
	}
}

func TestJWKPaddingY(t *testing.T) {
	key := `{
    "kty": "EC",
    "crv": "P-256",
    "x": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs",
    "y": "nPTIABcDASY6FNGSNfHCB51tY7qChtgzeVazOtLrwQ"
  }`
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(key))
	if err == nil {
		t.Errorf("Expected key with short y to fail unmarshalling")
	}
	if !strings.Contains(err.Error(), "wrong length for y") {
		t.Errorf("Wrong error for short y, got %q", err)
	}
	if jwk.Valid() {
		t.Errorf("Expected key to be invalid, but it was valid.")
	}
}
