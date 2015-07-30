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
	"encoding/json"
	"fmt"
	"testing"
)

func TestCompactParseJWS(t *testing.T) {
	// Should parse
	msg := "eyJhbGciOiJYWVoifQ.cGF5bG9hZA.c2lnbmF0dXJl"
	_, err := ParseSigned(msg)
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
		t.Error("Unable to parse valid message.")
	}
	if len(jws.Signatures) != 1 {
		t.Error("Too many or too few signatures.")
	}
	sig := jws.Signatures[0]
	if sig.Header.JsonWebKey == nil {
		t.Error("No JWK in signature header.")
	}
	payload, _, err := jws.Verify(sig.Header.JsonWebKey)
	if err != nil {
		t.Error(fmt.Sprintf("Signature did not validate: %v", err))
	}
	if string(payload) != "foo\n" {
		t.Error(fmt.Sprintf("Payload was incorrect: '%s' should have been 'foo\\n'", string(payload)))
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
	if sig.Header.JsonWebKey == nil {
		t.Error("No JWK in signature header.")
	}
	payload, _, err := jws.Verify(sig.Header.JsonWebKey)
	if err != nil {
		t.Error(fmt.Sprintf("Signature did not validate: %v", err))
	}
	expected := "{\"contact\":[\"mailto:foo@bar.com\"]}"
	if string(payload) != expected {
		t.Error(fmt.Sprintf("Payload was incorrect: '%s' should have been '%s'", string(payload), expected))
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesRSA(t *testing.T) {
	rsaPublicKey, err := LoadPublicKey(fromBase64Bytes(`
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
		payload, _, err := obj.Verify(rsaPublicKey)
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
	ecPublicKeyP256, err := LoadPublicKey(fromBase64Bytes("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIg62jq6FyL1otEj9Up7S35BUrwGF9TVrAzrrY1rHUKZqYIGEg67u/imjgadVcr7y9Q32I0gB8W8FHqbqt696rA=="))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP384, err := LoadPublicKey(fromBase64Bytes("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPXsVlqCtN2oTY+F+hFZm3M0ldYpb7IeeJM5wYmT0k1RaqzBFDhDMNnYK5Q5x+OyssZrAtHgYDFw02AVJhhng/eHRp7mqmL/vI3wbxJtrLKYldIbBA+9fYBQcKeibjlu5"))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP521, err := LoadPublicKey(fromBase64Bytes("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAa2w3MMJ5FWD6tSf68G+Wy5jIhWXOD3IA7pE5IC/myQzo1lWcD8KS57SM6nm4POtPcxyLmDhL7FLuh8DKoIZyvtAAdK8+tOQP7XXRlT2bkvzIuazp05It3TAPu00YzTIpKfDlc19Y1lvf7etrbFqhShD92B+hHmhT4ddrdbPCBDW8hvU="))
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
		payload, _, err := obj.Verify(ecPublicKeys[i])
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
		payload, _, err := obj.Verify(hmacTestKey)
		if err != nil {
			t.Error("unable to verify message", msg, err)
			continue
		}
		if string(payload) != "Lorem ipsum dolor sit amet" {
			t.Error("payload is not what we expected for msg", msg)
		}
	}
}

func TestMarshalUnmarshalJWS(t *testing.T) {
	input := `{"jws":{"header":{"alg":"RS256","jwk":{"kty":"RSA","n":"7ixeydcbxxppzxrBphrW1atUiEZqTpiHDpI-79olav5XxAgWolHmVsJyxzoZXRxmtED8PF9-EICZWBGdSAL9ZTD0hLUCIsPcpdgT_LqNW3Sh2b2caPL2hbMF7vsXvnCGg9varpnHWuYTyRrCLUF9vM7ES-V3VCYTa7LcCSRm56Gg9r19qar43Z9kIKBBxpgt723v2cC4bmLmoAX2s217ou3uCpCXGLOeV_BesG4--Nl3pso1VhCfO85wEWjmW6lbv7Kg4d7Jdkv5DjDZfJ086fkEAYZVYGRpIgAvJBH3d3yKDCrSByUEud1bWuFjQBmMaeYOrVDXO_mbYg5PwUDMhw","e":"AQAB"}},"protected":"eyJub25jZSI6IjhISWVwVU5GWlVhLWV4S1RyWFZmNGcifQ","payload":"eyJjb250YWN0IjpbIm1haWx0bzpmb29AYmFyLmNvbSJdfQ","signature":"AyvVGMgXsQ1zTdXrZxE_gyO63pQgotL1KbI7gv6Wi8I7NRy0iAOkDAkWcTQT9pcCYApJ04lXfEDZfP5i0XgcFUm_6spxi5mFBZU-NemKcvK9dUiAbXvb4hB3GnaZtZiuVnMQUb_ku4DOaFFKbteA6gOYCnED_x7v0kAPHIYrQnvIa-KZ6pTajbV9348zgh9TL7NgGIIsTcMHd-Jatr4z1LQ0ubGa8tS300hoDhVzfoDQaEetYjCo1drR1RmdEN1SIzXdHOHfubjA3ZZRbrF_AJnNKpRRoIwzu1VayOhRmdy1qVSQZq_tENF4VrQFycEL7DhG7JLoXC4T2p1urwMlsw"}}`

	parsed := struct {
		JWS *JsonWebSignature `json:"jws"`
	}{}

	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		t.Error("unable to unmarshal JSON JWS")
	}

	if parsed.JWS == nil {
		t.Error("JWS did not correctly unmarshal")
	}

	serialized, err := json.Marshal(parsed)
	if err != nil {
		t.Error("unable to marshal JSON JWS")
	}

	err = json.Unmarshal(serialized, &parsed)
	if err != nil {
		t.Error("unable to unmarshal marshaled JSON JWS")
	}

	if parsed.JWS == nil {
		t.Error("JWS did not correctly unmarshal from marshaled JSON JWS")
	}
}
