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
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const trustedCA = `
-----BEGIN CERTIFICATE-----
MIIE8DCCAtigAwIBAgIJAPgBgSSm5PSpMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCVRydXN0ZWRDQTAeFw0yMDEwMDQyMjU0MzlaFw00MDEwMDQyMjU0MzlaMBQx
EjAQBgNVBAMMCVRydXN0ZWRDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAJ+o4csEF8uhudNfBgOilhJbJT4D+gLTJT2l7+YEaRnJsyKnaaMYTZl3j+6z
8eRPCIx0wkeVvy9H0XXARkXPylycpFrFdOOE+jG7n/KpglOgD4cnpJEc2cZOGnxi
d1EiVEoFS9iD1L+SZG0XLfczfGCi970lK1UfBkADrjxXPdUmml+LFlQbLwdjw29e
b8heaYep3ltXpyfy2W0mgLakqV+mWqPzcp4dWjohSrOWr/iZSWTVLKlXyKvj3nfC
lcXU5FqDSlU5m6tbxhfscEvG2n12TzpGTNSez7my3qxNaAFf1rd/+RvJYjJ4gelH
O9ZF9POqOxdoRgZca2SQetRaUlrYbJTY9cjKEJLloo83I65vWDqgMREChzpMorKz
ZCeqCVgsgAdo75kiCW1fHY6MvBFk2x9kfZqwv/Dp+vyv22bOVa7ob84CEWbRYMIt
wCXRXrewAkvCHFvB6Uoz2Qn2c+3jWzlyRNCucfaPtWnNzRaG6lVm9ieucQI/+Ij4
XwuZmmPzOAvKlXadVXNlnsExkrAabc6UJEyqKI7raSeJaR/8RLLfxTDSv3UuWY8v
I2QMdS1f6fC8VJKTYMfbdnIw4RQ9Eqi2EmNPgJ4I2mTilG12pRxl/dvfFTl/7/TM
Mu6jCLNvJnm3B96at1Y4evWoee51EcvpkNnwotyPLtJFpEMLAgMBAAGjRTBDMB0G
A1UdDgQWBBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNVHRMBAf8ECDAGAQH/AgEB
MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAB9WBvqUM+tM+1JAS
YmUmRKjYlrKUYwNTzgrAyyiYLWzp9cmcw+3hbAjDV0Lu1Im8QQ0eRdq2H8103JYd
+nJJx+zlJ04s3pms02uZf8s05XJPSqlYb03uyfZ5uQcOAsRAPHeXaxEmZ/K6PGqO
14O3anXb5u+Qq2cb7DGG/Qcek8iX8vI5RqxvLGOOD9z9mpqE9M6aTsjuBVSLM3aQ
yIIkRk3deXiOfZd8d+0pShKgVBSrAC8c7A+Yps/r/vSGmN8L+LDoNzfx4NaPLBzu
dgiKVpYYgjFEnDzYItWpyxkPVjfMxPEQkz8choJaYNuoROpZtEnSFb4MFHlYGqhO
ZYETsYL3BRCHp0WysA3KuXTyA2Tmr+503Xw0btO2ieGEOCe3v/Yc7WGQX3RRAdci
2TkBISG6QlH5FzeV11hPriKEMSFHFdJvVrtRORtkGPeE6DUjHQ8MSK8Vm0niKT5P
l9GLvIrBN00Pa+YUX0j1xaCY0aj0oxKDFIdyWTn6aR/q9M7CfW6H0fNjPu56+jit
q+yQijumIkI5MTlbj0ja51yN62/tNhpTZx/NXpWjgZ+S/668/BJ2veV99PGuQCss
jlhHfN8RbHaPuKTKLLslkTvtpIYTc6F9TmcnVAdyKxN8e1XHcV4WrIOzgegVE4IF
48TF8WeXgGnsH4Bvob3cZcqWA+w=
-----END CERTIFICATE-----`

const intermediateCA = `
-----BEGIN CERTIFICATE-----
MIIEDzCCAfegAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVHJ1
c3RlZENBMB4XDTIwMTAwNDIzMDMzM1oXDTQwMTAwNDIzMDMzM1owGTEXMBUGA1UE
AwwOSW50ZXJtZWRpYXRlQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDiKADoUoaNvD4yCLPySuPR1saLWHNRlt2nqbd7smwB1quNKnKwAKKnLyaBUHIC
FrQjCTA7IF7KUndVU0vutMFzn6hKuliZMYbwDQgx6x8u34m8Ar8cAg/AJPgT5Kk6
Ds8soUaTzRG/GXVjGll0ArjRp97LmOW1Tc53R4YJji6eTThgb4Al6XDou2AeEMNY
C46yqafwzOvHOnzSQwy8IwdcFjNKry15pvutIK3UhZscAmfbNEN5ou3miWcz3PuV
GORxKAqlA4mYoJWE2AF52fgNTYcTFCDdiThaFSBzgqEgFoDzzROhf1B+/bSJ4gUL
K9YQxpXVmt8/tlvXjNygDj1LAgMBAAGjZjBkMB0GA1UdDgQWBBTZZOBbEfV70Ocm
9RIM16yhAw4SyjAfBgNVHSMEGDAWgBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOC
AgEADfEtLh3YDabrTsx+KmJ1f8ybwdltgI3gPiubd5RcYcoO3Pd33/INJDMkJYfL
CrSDLI5Y94szOUhkP/rSwrUgJErnPSPUEW11GgA230d7vjc3bFJO/bPb2ZAwm/eC
7dMMyyDH/2Wty7h7SOuXXJljZYIvuavJymZxsmkDAu7MtdntHVLr5bruEYvM9IKa
d9YZSchRP1Q3kIZuTmNvBgLGwrVw/UcOpczajULNNzPUNPDFs9Zo04tx/YF1R1fO
GUhif13DMk+6JU7zUXZL3iqOSkxBRrlMQX6nKAQ68cMqO2UsrfXBqH5xm3O9+Nxs
fN3CkkTcyBcvVFMaMe0670lCh3DcFOMDt2YdlqS5tEsBn3TdOFKSjv2dVnT2eeXc
q5IvuC4nkEXzZDROfQVrnraBhHOiyLAlfwhA1LHZGlJfNZaWRDdXHKV+pIMr2JyO
v/hf9aaWzjwyy7FJwn3yrEwHGfBgx0vgKPj6l6N8qxQ6l1XMyANx4ExlpXfffx+C
PWV9eeMi4Wh6V9641LesQnlOGgL5R03jQRjaicp3nvzsNElDEgPq0s9PE8s6weFK
Bz5ykrw/Gg4QWmw6MfwjOX5Fu1oJF9ABoCFD5umvKhpoJkcT8aYM0+E1xiEAx64u
Wq2b2GCGP4wMEZuqCcE72fiue295ovPkNsbEjTQk/ijWza0=
-----END CERTIFICATE-----`

func TestEmbeddedHMAC(t *testing.T) {
	// protected: {"alg":"HS256", "jwk":{"kty":"oct", "k":"MTEx"}}, aka HMAC key.
	msg := `{"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ","protected":"eyJhbGciOiJIUzI1NiIsICJqd2siOnsia3R5Ijoib2N0IiwgImsiOiJNVEV4In19","signature":"lvo41ZZsuHwQvSh0uJtEXRR3vmuBJ7in6qMoD7p9jyo"}`

	_, err := ParseSigned(msg)
	if err == nil {
		t.Error("should not allow parsing JWS with embedded JWK with HMAC key")
	}
}

func TestCompactParseJWS(t *testing.T) {
	// Should parse
	msg := "eyJhbGciOiJYWVoifQ.cGF5bG9hZA.c2lnbmF0dXJl"
	_, err := ParseSigned(msg)
	if err != nil {
		t.Error("Unable to parse valid message:", err)
	}

	// Should parse (detached signature missing payload)
	msg = "eyJhbGciOiJYWVoifQ..c2lnbmF0dXJl"
	_, err = ParseSigned(msg)
	if err != nil {
		t.Error("Unable to parse valid message:", err)
	}

	// Messages that should fail to parse
	failures := []string{
		// Not enough parts
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA",
		// Invalid signature
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA.////",
		// Invalid payload
		"eyJhbGciOiJYWVoifQ.////.c2lnbmF0dXJl",
		// Invalid header
		"////.eyJhbGciOiJYWVoifQ.c2lnbmF0dXJl",
		// Invalid header
		"cGF5bG9hZA.cGF5bG9hZA.c2lnbmF0dXJl",
	}

	for i := range failures {
		_, err = ParseSigned(failures[i])
		if err == nil {
			t.Error("Able to parse invalid message")
		}
	}
}

func TestFullParseJWS(t *testing.T) {
	// Messages that should succeed to parse
	successes := []string{
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"e30\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"},{\"protected\":\"e30\",\"signature\":\"CUJD\"}]}",
	}

	for i := range successes {
		_, err := ParseSigned(successes[i])
		if err != nil {
			t.Error("Unble to parse valid message", err, successes[i])
		}
	}

	// Messages that should fail to parse
	failures := []string{
		// Empty
		"{}",
		// Invalid JSON
		"{XX",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"###\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid payload
		"{\"payload\":\"###\",\"signatures\":[{\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid payload
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"e30\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"###\"}]}",
	}

	for i := range failures {
		_, err := ParseSigned(failures[i])
		if err == nil {
			t.Error("Able to parse invalid message", err, failures[i])
		}
	}
}

func TestRejectUnprotectedJWSNonce(t *testing.T) {
	// No need to test compact, since that's always protected

	// Flattened JSON
	input := `{
		"header": { "nonce": "should-cause-an-error" },
		"payload": "does-not-matter",
		"signature": "does-not-matter"
	}`
	_, err := ParseSigned(input)
	if err == nil {
		t.Error("JWS with an unprotected nonce parsed as valid.")
	} else if err != ErrUnprotectedNonce {
		t.Errorf("Improper error for unprotected nonce: %v", err)
	}

	// Full JSON
	input = `{
		"payload": "does-not-matter",
 		"signatures": [{
 			"header": { "nonce": "should-cause-an-error" },
			"signature": "does-not-matter"
		}]
	}`
	_, err = ParseSigned(input)
	if err == nil {
		t.Error("JWS with an unprotected nonce parsed as valid.")
	} else if err != ErrUnprotectedNonce {
		t.Errorf("Improper error for unprotected nonce: %v", err)
	}
}

func TestVerifyFlattenedWithIncludedUnprotectedKey(t *testing.T) {
	input := `{
			"header": {
					"alg": "RS256",
					"jwk": {
							"e": "AQAB",
							"kty": "RSA",
							"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
					}
			},
			"payload": "Zm9vCg",
			"signature": "hRt2eYqBd_MyMRNIh8PEIACoFtmBi7BHTLBaAhpSU6zyDAFdEBaX7us4VB9Vo1afOL03Q8iuoRA0AT4akdV_mQTAQ_jhTcVOAeXPr0tB8b8Q11UPQ0tXJYmU4spAW2SapJIvO50ntUaqU05kZd0qw8-noH1Lja-aNnU-tQII4iYVvlTiRJ5g8_CADsvJqOk6FcHuo2mG643TRnhkAxUtazvHyIHeXMxydMMSrpwUwzMtln4ZJYBNx4QGEq6OhpAD_VSp-w8Lq5HOwGQoNs0bPxH1SGrArt67LFQBfjlVr94E1sn26p4vigXm83nJdNhWAMHHE9iV67xN-r29LT-FjA"
	}`

	jws, err := ParseSigned(input)
	if err != nil {
		t.Fatal("Unable to parse valid message", err)
	}
	if len(jws.Signatures) != 1 {
		t.Error("Too many or too few signatures.")
	}
	sig := jws.Signatures[0]
	if sig.Header.JSONWebKey == nil {
		t.Error("No JWK in signature header.")
	}
	payload, err := jws.Verify(sig.Header.JSONWebKey)
	if err != nil {
		t.Errorf("Signature did not validate: %v", err)
	}
	if string(payload) != "foo\n" {
		t.Errorf("Payload was incorrect: '%s' should have been 'foo\\n'", string(payload))
	}
}

// Test verification of a detached signature
func TestDetachedVerifyJWS(t *testing.T) {
	rsaPublicKey, err := x509.ParsePKIXPublicKey(fromBase64Bytes(`
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3aLSGwbeX0ZA2Ha+EvELaIFGzO
		91+Q15JQc/tdGdCgGW3XAbrh7ZUhDh1XKzbs+UOQxqn3Eq4YOx18IG0WsJSuCaHQIxnDlZ
		t/GP8WLwjMC0izlJLm2SyfM/EEoNpmTC3w6MQ2dHK7SZ9Zoq+sKijQd+V7CYdr8zHMpDrd
		NKoEcR0HjmvzzdMoUChhkGH5TaNbZyollULTggepaYUKS8QphqdSDMWiSetKG+g6V87lv6
		CVYyK1FF6g7Esp5OOj5pNn3/bmF+7V+b7TvK91NCIlURCjE9toRgNoIP4TDnWRn/vvfZ3G
		zNrtWmlizqz3r5KdvIs71ahWgMUSD4wfazrwIDAQAB`))
	if err != nil {
		t.Fatal(err)
	}

	sampleMessages := []string{
		"eyJhbGciOiJSUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.YHX849fvekz6wJGeyqnQhFqyHFcUXNJKj3o2w3ddR46YLlsCopUJrlifRU_ZuTWzpYxt5oC--T2eoqMhlCvltSWrE5_1_EumqiMfAYsZULx9E6Jns7q3w7mttonYFSIh7aR3-yg2HMMfTCgoAY1y_AZ4VjXwHDcZ5gu1oZDYgvZF4uXtCmwT6e5YtR1m8abiWPF8BgoTG_BD3KV6ClLj_QQiNFdfdxAMDw7vKVOKG1T7BFtz6cDs2Q3ILS4To5E2IjcVSSYS8mi77EitCrWmrqbK_G3WCdKeUFGnMnyuKXaCDy_7FLpAZ6Z5RomRr5iskXeJZdZqIKcJV8zl4fpsPA",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
	}

	for _, msg := range sampleMessages {
		obj, err := ParseSigned(msg)
		if err != nil {
			t.Error("unable to parse message", msg, err)
			continue
		}
		payload := obj.payload
		obj.payload = nil
		err = obj.DetachedVerify(payload, rsaPublicKey)
		if err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
		idx, _, err := obj.DetachedVerifyMulti(payload, rsaPublicKey)
		if idx != 0 || err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
	}
}

func TestVerifyFlattenedWithPrivateProtected(t *testing.T) {
	// The protected field contains a Private Header Parameter name, per
	// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
	// Base64-decoded, it's '{"nonce":"8HIepUNFZUa-exKTrXVf4g"}'
	input := `{"header":{"alg":"RS256","jwk":{"kty":"RSA","n":"7ixeydcbxxppzxrBphrW1atUiEZqTpiHDpI-79olav5XxAgWolHmVsJyxzoZXRxmtED8PF9-EICZWBGdSAL9ZTD0hLUCIsPcpdgT_LqNW3Sh2b2caPL2hbMF7vsXvnCGg9varpnHWuYTyRrCLUF9vM7ES-V3VCYTa7LcCSRm56Gg9r19qar43Z9kIKBBxpgt723v2cC4bmLmoAX2s217ou3uCpCXGLOeV_BesG4--Nl3pso1VhCfO85wEWjmW6lbv7Kg4d7Jdkv5DjDZfJ086fkEAYZVYGRpIgAvJBH3d3yKDCrSByUEud1bWuFjQBmMaeYOrVDXO_mbYg5PwUDMhw","e":"AQAB"}},"protected":"eyJub25jZSI6IjhISWVwVU5GWlVhLWV4S1RyWFZmNGcifQ","payload":"eyJjb250YWN0IjpbIm1haWx0bzpmb29AYmFyLmNvbSJdfQ","signature":"AyvVGMgXsQ1zTdXrZxE_gyO63pQgotL1KbI7gv6Wi8I7NRy0iAOkDAkWcTQT9pcCYApJ04lXfEDZfP5i0XgcFUm_6spxi5mFBZU-NemKcvK9dUiAbXvb4hB3GnaZtZiuVnMQUb_ku4DOaFFKbteA6gOYCnED_x7v0kAPHIYrQnvIa-KZ6pTajbV9348zgh9TL7NgGIIsTcMHd-Jatr4z1LQ0ubGa8tS300hoDhVzfoDQaEetYjCo1drR1RmdEN1SIzXdHOHfubjA3ZZRbrF_AJnNKpRRoIwzu1VayOhRmdy1qVSQZq_tENF4VrQFycEL7DhG7JLoXC4T2p1urwMlsw"}`

	jws, err := ParseSigned(input)
	if err != nil {
		t.Error("Unable to parse valid message.")
	}
	if len(jws.Signatures) != 1 {
		t.Error("Too many or too few signatures.")
	}
	sig := jws.Signatures[0]
	if sig.Header.JSONWebKey == nil {
		t.Error("No JWK in signature header.")
	}
	payload, err := jws.Verify(sig.Header.JSONWebKey)
	if err != nil {
		t.Errorf("Signature did not validate: %v", err)
	}
	expected := "{\"contact\":[\"mailto:foo@bar.com\"]}"
	if string(payload) != expected {
		t.Errorf("Payload was incorrect: '%s' should have been '%s'", string(payload), expected)
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesRSA(t *testing.T) {
	rsaPublicKey, err := x509.ParsePKIXPublicKey(fromBase64Bytes(`
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3aLSGwbeX0ZA2Ha+EvELaIFGzO
		91+Q15JQc/tdGdCgGW3XAbrh7ZUhDh1XKzbs+UOQxqn3Eq4YOx18IG0WsJSuCaHQIxnDlZ
		t/GP8WLwjMC0izlJLm2SyfM/EEoNpmTC3w6MQ2dHK7SZ9Zoq+sKijQd+V7CYdr8zHMpDrd
		NKoEcR0HjmvzzdMoUChhkGH5TaNbZyollULTggepaYUKS8QphqdSDMWiSetKG+g6V87lv6
		CVYyK1FF6g7Esp5OOj5pNn3/bmF+7V+b7TvK91NCIlURCjE9toRgNoIP4TDnWRn/vvfZ3G
		zNrtWmlizqz3r5KdvIs71ahWgMUSD4wfazrwIDAQAB`))
	if err != nil {
		panic(err)
	}

	rsaSampleMessages := []string{
		"eyJhbGciOiJSUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.YHX849fvekz6wJGeyqnQhFqyHFcUXNJKj3o2w3ddR46YLlsCopUJrlifRU_ZuTWzpYxt5oC--T2eoqMhlCvltSWrE5_1_EumqiMfAYsZULx9E6Jns7q3w7mttonYFSIh7aR3-yg2HMMfTCgoAY1y_AZ4VjXwHDcZ5gu1oZDYgvZF4uXtCmwT6e5YtR1m8abiWPF8BgoTG_BD3KV6ClLj_QQiNFdfdxAMDw7vKVOKG1T7BFtz6cDs2Q3ILS4To5E2IjcVSSYS8mi77EitCrWmrqbK_G3WCdKeUFGnMnyuKXaCDy_7FLpAZ6Z5RomRr5iskXeJZdZqIKcJV8zl4fpsPA",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
		"eyJhbGciOiJSUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.rQPz0PDh8KyE2AX6JorgI0MLwv-qi1tcWlz6tuZuWQG1hdrlzq5tR1tQg1evYNc_SDDX87DWTSKXT7JEqhKoFixLfZa13IJrOc7FB8r5ZLx7OwOBC4F--OWrvxMA9Y3MTJjPN3FemQePUo-na2vNUZv-YgkcbuOgbO3hTxwQ7j1JGuqy-YutXOFnccdXvntp3t8zYZ4Mg1It_IyL9pzgGqHIEmMV1pCFGHsDa-wStB4ffmdhrADdYZc0q_SvxUdobyC_XzZCz9ENzGIhgwYxyyrqg7kjqUGoKmCLmoSlUFW7goTk9IC5SXdUyLPuESxOWNfHoRClGav230GYjPFQFA",
		"eyJhbGciOiJQUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.UTtxjsv_6x4CdlAmZfAW6Lun3byMjJbcwRp_OlPH2W4MZaZar7aql052mIB_ddK45O9VUz2aphYVRvKPZY8WHmvlTUU30bk0z_cDJRYB9eIJVMOiRCYj0oNkz1iEZqsP0YgngxwuUDv4Q4A6aJ0Bo5E_rZo3AnrVHMHUjPp_ZRRSBFs30tQma1qQ0ApK4Gxk0XYCYAcxIv99e78vldVRaGzjEZmQeAVZx4tGcqZP20vG1L84nlhSGnOuZ0FhR8UjRFLXuob6M7EqtMRoqPgRYw47EI3fYBdeSivAg98E5S8R7R1NJc7ef-l03RvfUSY0S3_zBq_4PlHK6A-2kHb__w",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
		"eyJhbGciOiJSUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.rQPz0PDh8KyE2AX6JorgI0MLwv-qi1tcWlz6tuZuWQG1hdrlzq5tR1tQg1evYNc_SDDX87DWTSKXT7JEqhKoFixLfZa13IJrOc7FB8r5ZLx7OwOBC4F--OWrvxMA9Y3MTJjPN3FemQePUo-na2vNUZv-YgkcbuOgbO3hTxwQ7j1JGuqy-YutXOFnccdXvntp3t8zYZ4Mg1It_IyL9pzgGqHIEmMV1pCFGHsDa-wStB4ffmdhrADdYZc0q_SvxUdobyC_XzZCz9ENzGIhgwYxyyrqg7kjqUGoKmCLmoSlUFW7goTk9IC5SXdUyLPuESxOWNfHoRClGav230GYjPFQFA",
	}

	for _, msg := range rsaSampleMessages {
		obj, err := ParseSigned(msg)
		if err != nil {
			t.Error("unable to parse message", msg, err)
			continue
		}
		payload, err := obj.Verify(rsaPublicKey)
		if err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
		if string(payload) != "Lorem ipsum dolor sit amet" {
			t.Error("payload is not what we expected for msg", msg)
		}
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesEC(t *testing.T) {
	ecPublicKeyP256, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIg62jq6FyL1otEj9Up7S35BUrwGF9TVrAzrrY1rHUKZqYIGEg67u/imjgadVcr7y9Q32I0gB8W8FHqbqt696rA=="))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP384, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPXsVlqCtN2oTY+F+hFZm3M0ldYpb7IeeJM5wYmT0k1RaqzBFDhDMNnYK5Q5x+OyssZrAtHgYDFw02AVJhhng/eHRp7mqmL/vI3wbxJtrLKYldIbBA+9fYBQcKeibjlu5"))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP521, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAa2w3MMJ5FWD6tSf68G+Wy5jIhWXOD3IA7pE5IC/myQzo1lWcD8KS57SM6nm4POtPcxyLmDhL7FLuh8DKoIZyvtAAdK8+tOQP7XXRlT2bkvzIuazp05It3TAPu00YzTIpKfDlc19Y1lvf7etrbFqhShD92B+hHmhT4ddrdbPCBDW8hvU="))
	if err != nil {
		panic(err)
	}

	ecPublicKeys := []interface{}{ecPublicKeyP256, ecPublicKeyP384, ecPublicKeyP521}

	ecSampleMessages := []string{
		"eyJhbGciOiJFUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.MEWJVlvGRQyzMEGOYm4rwuiwxrX-6LjnlbaRDAuhwmnBm2Gtn7pRpGXRTMFZUXsSGDz2L1p-Hz1qn8j9bFIBtQ",
		"eyJhbGciOiJFUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.nbdjPnJPYQtVNNdBIx8-KbFKplTxrz-hnW5UNhYUY7SBkwHK4NZnqc2Lv4DXoA0aWHq9eiypgOh1kmyPWGEmqKAHUx0xdIEkBoHk3ZsbmhOQuq2jL_wcMUG6nTWNhLrB",
		"eyJhbGciOiJFUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g",
	}

	for i, msg := range ecSampleMessages {
		obj, err := ParseSigned(msg)
		if err != nil {
			t.Error("unable to parse message", msg, err)
			continue
		}
		payload, err := obj.Verify(ecPublicKeys[i])
		if err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
		if string(payload) != "Lorem ipsum dolor sit amet" {
			t.Error("payload is not what we expected for msg", msg)
		}
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesHMAC(t *testing.T) {
	hmacTestKey := fromHexBytes("DF1FA4F36FFA7FC42C81D4B3C033928D")

	hmacSampleMessages := []string{
		"eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.W5tc_EUhxexcvLYEEOckyyvdb__M5DQIVpg6Nmk1XGM",
		"eyJhbGciOiJIUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.sBu44lXOJa4Nd10oqOdYH2uz3lxlZ6o32QSGHaoGdPtYTDG5zvSja6N48CXKqdAh",
		"eyJhbGciOiJIUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.M0yR4tmipsORIix-BitIbxEPGaxPchDfj8UNOpKuhDEfnb7URjGvCKn4nOlyQ1z9mG1FKbwnqR1hOVAWSzAU_w",
	}

	for _, msg := range hmacSampleMessages {
		obj, err := ParseSigned(msg)
		if err != nil {
			t.Error("unable to parse message", msg, err)
			continue
		}
		payload, err := obj.Verify(hmacTestKey)
		if err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
		if string(payload) != "Lorem ipsum dolor sit amet" {
			t.Error("payload is not what we expected for msg", msg)
		}
	}
}

func TestHeaderFieldsCompact(t *testing.T) {
	msg := "eyJhbGciOiJFUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g"

	obj, err := ParseSigned(msg)
	if err != nil {
		t.Fatal("unable to parse message", msg, err)
	}
	if obj.Signatures[0].Header.Algorithm != "ES512" {
		t.Error("merged header did not contain expected alg value")
	}
	if obj.Signatures[0].Protected.Algorithm != "ES512" {
		t.Error("protected header did not contain expected alg value")
	}
	if obj.Signatures[0].Unprotected.Algorithm != "" {
		t.Error("unprotected header contained an alg value")
	}
}

func TestHeaderFieldsFull(t *testing.T) {
	msg := `{"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ","protected":"eyJhbGciOiJFUzUxMiJ9","header":{"custom":"test"},"signature":"AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g"}`

	obj, err := ParseSigned(msg)
	if err != nil {
		t.Fatal("unable to parse message", msg, err)
	}
	if obj.Signatures[0].Header.Algorithm != "ES512" {
		t.Error("merged header did not contain expected alg value")
	}
	if obj.Signatures[0].Protected.Algorithm != "ES512" {
		t.Error("protected header did not contain expected alg value")
	}
	if obj.Signatures[0].Unprotected.Algorithm != "" {
		t.Error("unprotected header contained an alg value")
	}
	if obj.Signatures[0].Unprotected.ExtraHeaders["custom"] != "test" {
		t.Error("unprotected header did not contain custom header value")
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestErrorMissingPayloadJWS(t *testing.T) {
	_, err := (&rawJSONWebSignature{}).sanitized()
	if err == nil {
		t.Error("was able to parse message with missing payload")
	}
	if !strings.Contains(err.Error(), "missing payload") {
		t.Errorf("unexpected error message, should contain 'missing payload': %s", err)
	}
}

// Test that a null value in the header doesn't panic
func TestNullHeaderValue(t *testing.T) {
	msg := `{
   "payload":
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
     tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
   "protected":"eyJhbGciOiJFUzI1NiIsIm5vbmNlIjpudWxsfQ",
   "header":
    {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
   "signature":
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
     lSApmWQxfKTUJqPP3-Kg6NU1Q"
  }`

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseSigned panic'd when parsing a message with a null protected header value")
		}
	}()
	if _, err := ParseSigned(msg); err != nil {
		t.Fatal(err)
	}
}

// Test for bug:
// https://github.com/square/go-jose/issues/157
func TestEmbedJWKBug(t *testing.T) {
	signerKey := SigningKey{
		Key: &JSONWebKey{
			Key:   rsaTestKey,
			KeyID: "rsa-test-key",
		},
		Algorithm: RS256,
	}

	signer, err := NewSigner(signerKey, &SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatal(err)
	}

	signerNoEmbed, err := NewSigner(signerKey, &SignerOptions{EmbedJWK: false})
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatal(err)
	}

	jwsNoEmbed, err := signerNoEmbed.Sign([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatal(err)
	}

	// This used to panic with:
	// json: error calling MarshalJSON for type *jose.JSONWebKey: square/go-jose: unknown key type '%!s(<nil>)'
	output := jws.FullSerialize()
	outputNoEmbed := jwsNoEmbed.FullSerialize()

	// Expected output with embed set to true is a JWS with the public JWK embedded, with kid header empty.
	// Expected output with embed set to false is that we set the kid header for key identification instead.
	parsed, err := ParseSigned(output)
	if err != nil {
		t.Fatal(err)
	}

	parsedNoEmbed, err := ParseSigned(outputNoEmbed)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Signatures[0].Header.KeyID != "" {
		t.Error("expected kid field in protected header to be empty")
	}
	if parsed.Signatures[0].Header.JSONWebKey.KeyID != "rsa-test-key" {
		t.Error("expected rsa-test-key to be kid in embedded JWK in protected header")
	}
	if parsedNoEmbed.Signatures[0].Header.KeyID != "rsa-test-key" {
		t.Error("expected kid field in protected header to be rsa-test-key")
	}
	if parsedNoEmbed.Signatures[0].Header.JSONWebKey != nil {
		t.Error("expected no embedded JWK to be present")
	}
}

func TestJWSWithCertificateChain(t *testing.T) {
	signerKey := SigningKey{
		Key:       rsaTestKey,
		Algorithm: RS256,
	}

	certs := []string{
		// CN=TrustedSigner, signed by IntermediateCA
		"MIIDOjCCAiKgAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOSW50ZXJtZWRpYXRlQ0EwHhcNMjAxMDA0MjMzNDA3WhcNNDAxMDA0MjMzNDA3WjAYMRYwFAYDVQQDDA1UcnVzdGVkU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAswje1TAIK6aBvvVbuf3bq0emTEDXsTnovRv7HArauy0Lc72Gai8tuc1WVAmw8byxqaNHnHTfIT66UxPBcktr59A9KW2NqNXtNlhVgyIcYFEBFgmKjItmHG2BTw8HIvUnrcneRY9w/gE74f+7BPl0WUE2jsKkf8cIvZso5osGoBwVRN5YP0aWersaXVpA+hVUbMuwUnAvLdvuSvXDtL6SDdisHV9rhZH2jRAj6BzmC4mAD9BATeFFqC1Nt+bo1d7TUNk/FEbjyzs6g9QCUsTTL2RoPFvdQYjnYoIl4tVClUGipeEXb3e84k/ZEUDC04ENCONM/BsQEHBcR0eylViD7QIDAQABo4GMMIGJMB0GA1UdDgQWBBQ5GmxMDIgf21y8SDTSMy2/bZjcLjAfBgNVHSMEGDAWgBTZZOBbEfV70Ocm9RIM16yhAw4SyjAOBgNVHQ8BAf8EBAMCA7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBgGA1UdEQQRMA+CDVRydXN0ZWRTaWduZXIwDQYJKoZIhvcNAQELBQADggEBAHS3KHVV/8H5eH2ZsDRsXyZkdqQlArlWCNK5I1xXW3jxnmAkrMu/Boin82foKLX7sNV33pdec8QMZMY3sTqr8OR+4haehYT9Dw6K4FEBtwRcuR08KducwnQO+kEeixkYtGpRX81hzLLdPHup9u+70WRsiSbgrYq9mV9bec+0uylbfh7ervNncIMTQvjZVkMnELrxe5l31UsZddHs2bzPbdlHuEhNmYxgzCXcFmpvv/WuuNiqVruQKzLYgR+F+eeE5UtmtE/gEBtPFHyLqQCoDcPqRY6B0VqNdcobPz4VOV8Fbf1HOzYEn7TdVglw6PTb5AXQ7/wnRss6SUofg6wzdzY=",
		// CN=IntermediateCA, signed by TrustedCA
		"MIIEDzCCAfegAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVHJ1c3RlZENBMB4XDTIwMTAwNDIzMDMzM1oXDTQwMTAwNDIzMDMzM1owGTEXMBUGA1UEAwwOSW50ZXJtZWRpYXRlQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiKADoUoaNvD4yCLPySuPR1saLWHNRlt2nqbd7smwB1quNKnKwAKKnLyaBUHICFrQjCTA7IF7KUndVU0vutMFzn6hKuliZMYbwDQgx6x8u34m8Ar8cAg/AJPgT5Kk6Ds8soUaTzRG/GXVjGll0ArjRp97LmOW1Tc53R4YJji6eTThgb4Al6XDou2AeEMNYC46yqafwzOvHOnzSQwy8IwdcFjNKry15pvutIK3UhZscAmfbNEN5ou3miWcz3PuVGORxKAqlA4mYoJWE2AF52fgNTYcTFCDdiThaFSBzgqEgFoDzzROhf1B+/bSJ4gULK9YQxpXVmt8/tlvXjNygDj1LAgMBAAGjZjBkMB0GA1UdDgQWBBTZZOBbEfV70Ocm9RIM16yhAw4SyjAfBgNVHSMEGDAWgBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEADfEtLh3YDabrTsx+KmJ1f8ybwdltgI3gPiubd5RcYcoO3Pd33/INJDMkJYfLCrSDLI5Y94szOUhkP/rSwrUgJErnPSPUEW11GgA230d7vjc3bFJO/bPb2ZAwm/eC7dMMyyDH/2Wty7h7SOuXXJljZYIvuavJymZxsmkDAu7MtdntHVLr5bruEYvM9IKad9YZSchRP1Q3kIZuTmNvBgLGwrVw/UcOpczajULNNzPUNPDFs9Zo04tx/YF1R1fOGUhif13DMk+6JU7zUXZL3iqOSkxBRrlMQX6nKAQ68cMqO2UsrfXBqH5xm3O9+NxsfN3CkkTcyBcvVFMaMe0670lCh3DcFOMDt2YdlqS5tEsBn3TdOFKSjv2dVnT2eeXcq5IvuC4nkEXzZDROfQVrnraBhHOiyLAlfwhA1LHZGlJfNZaWRDdXHKV+pIMr2JyOv/hf9aaWzjwyy7FJwn3yrEwHGfBgx0vgKPj6l6N8qxQ6l1XMyANx4ExlpXfffx+CPWV9eeMi4Wh6V9641LesQnlOGgL5R03jQRjaicp3nvzsNElDEgPq0s9PE8s6weFKBz5ykrw/Gg4QWmw6MfwjOX5Fu1oJF9ABoCFD5umvKhpoJkcT8aYM0+E1xiEAx64uWq2b2GCGP4wMEZuqCcE72fiue295ovPkNsbEjTQk/ijWza0=",
	}

	testCases := []struct {
		// Cert chain to embed in message
		chain []string
		// Intermediates & root certificate to verify against
		intermediates []string
		root          string
		// Should this test case verify?
		success bool
	}{
		{certs, nil, trustedCA, true},
		{certs, []string{intermediateCA}, trustedCA, true},
		{certs[0:1], nil, intermediateCA, true},
		{certs[0:1], nil, trustedCA, false},
		{[]string{}, nil, trustedCA, false},
	}

	for i, testCase := range testCases {
		signer, err := NewSigner(signerKey, &SignerOptions{
			ExtraHeaders: map[HeaderKey]interface{}{HeaderKey("x5c"): testCase.chain},
		})
		if err != nil {
			t.Fatal(err)
		}

		signed, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := ParseSigned(signed.FullSerialize())
		if err != nil {
			t.Fatal(err)
		}

		opts := x509.VerifyOptions{
			DNSName: "TrustedSigner",
			Roots:   x509.NewCertPool(),
		}

		ok := opts.Roots.AppendCertsFromPEM([]byte(testCase.root))
		if !ok {
			t.Fatal("failed to parse trusted root certificate")
		}

		if len(testCase.intermediates) > 0 {
			opts.Intermediates = x509.NewCertPool()
			for _, intermediate := range testCase.intermediates {
				ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
				if !ok {
					t.Fatal("failed to parse trusted root certificate")
				}
			}
		}

		chains, err := parsed.Signatures[0].Protected.Certificates(opts)
		if testCase.success && (len(chains) == 0 || err != nil) {
			t.Fatalf("failed to verify certificate chain for test case %d: %s", i, err)
		}
		if !testCase.success && (len(chains) != 0 && err == nil) {
			t.Fatalf("incorrectly verified certificate chain for test case %d (should fail)", i)
		}
	}
}

func TestDetachedCompactSerialization(t *testing.T) {
	msg := "eyJhbGciOiJSUzI1NiJ9.JC4wMg.W5tc_EUhxexcvLYEEOckyyvdb__M5DQIVpg6Nmk1XGM"
	exp := "eyJhbGciOiJSUzI1NiJ9..W5tc_EUhxexcvLYEEOckyyvdb__M5DQIVpg6Nmk1XGM"

	obj, err := ParseSigned(msg)
	if err != nil {
		t.Fatal(err)
	}

	ser, err := obj.DetachedCompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	if ser != exp {
		t.Fatalf("got '%s', expected '%s'", ser, exp)
	}

	obj, err = ParseDetached(ser, []byte("$.02"))
	if err != nil {
		t.Fatal(err)
	}

	ser, err = obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	if ser != msg {
		t.Fatalf("got '%s', expected '%s'", ser, msg)
	}
}

func TestJWSComputeAuthDataBase64(t *testing.T) {
	jws := JSONWebSignature{}

	_, err := jws.computeAuthData([]byte{0x01}, &Signature{
		original: &rawSignatureInfo{
			Protected: newBuffer([]byte("{!invalid-json}")),
		},
	})
	// Invalid header, should return error
	assert.NotNil(t, err)

	payload := []byte{0x01}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	b64TrueHeader := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","b64":true}`))
	b64FalseHeader := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","b64":false}`))

	data, err := jws.computeAuthData(payload, &Signature{
		original: &rawSignatureInfo{
			Protected: b64TrueHeader,
		},
	})
	assert.Nil(t, err)
	// Payload should be b64 encoded
	assert.Len(t, data, len(b64TrueHeader.base64())+len(encodedPayload)+1)

	data, err = jws.computeAuthData(payload, &Signature{
		original: &rawSignatureInfo{
			Protected: b64FalseHeader,
		},
	})
	assert.Nil(t, err)
	// Payload should *not* be b64 encoded
	assert.Len(t, data, len(b64FalseHeader.base64())+len(payload)+1)
}
