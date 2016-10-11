package jwt_test

import (
	"fmt"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var sharedKey = []byte("secret")
var signer, _ = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedKey}, &jose.SignerOptions{})

func ExampleParseSigned() {
	raw := `eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.gpHyA1B1H6X4a4Edm9wo7D3X2v3aLSDBDG2_5BzXYe0`
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		panic(err)
	}

	out := jwt.Claims{}
	if err := tok.Claims(sharedKey, &out); err != nil {
		panic(err)
	}
	fmt.Printf("iss: %s, sub: %s\n", out.Issuer, out.Subject)
	// Output: iss: issuer, sub: subject
}

func ExampleParseEncrypted() {
	key := []byte("itsa16bytesecret")
	raw := `eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..jg45D9nmr6-8awml.z-zglLlEw9MVkYHi-Znd9bSwc-oRGbqKzf9WjXqZxno.kqji2DiZHZmh-1bLF6ARPw`
	tok, err := jwt.ParseEncrypted(raw)
	if err != nil {
		panic(err)
	}

	out := jwt.Claims{}
	if err := tok.Claims(key, &out); err != nil {
		panic(err)
	}
	fmt.Printf("iss: %s, sub: %s\n", out.Issuer, out.Subject)
	//Output: iss: issuer, sub: subject
}

func ExampleSigned() {
	key := []byte("secret")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(raw)
	// Output: eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.gpHyA1B1H6X4a4Edm9wo7D3X2v3aLSDBDG2_5BzXYe0
}

func ExampleEncrypted() {
	key := []byte("itsa16bytesecret")
	enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	raw, err := jwt.Encrypted(enc).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(raw)
}

func ExampleSigned_multipleClaims() {
	c := &jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}
	c2 := struct {
		Scopes []string
	}{
		[]string{"foo", "bar"},
	}
	raw, err := jwt.Signed(signer).Claims(c).Claims(c2).CompactSerialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(raw)
	// Output: eyJhbGciOiJIUzI1NiJ9.eyJTY29wZXMiOlsiZm9vIiwiYmFyIl0sImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QifQ.esKOIsmwkudr_gnfnB4SngxIr-7pspd5XzG3PImfQ6Y
}

func ExampleJSONWebToken_Claims_map() {
	raw := `eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.gpHyA1B1H6X4a4Edm9wo7D3X2v3aLSDBDG2_5BzXYe0`
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		panic(err)
	}

	out := make(map[string]interface{})
	if err := tok.Claims(sharedKey, &out); err != nil {
		panic(err)
	}

	fmt.Printf("iss: %s, sub: %s\n", out["iss"], out["sub"])
	// Output: iss: issuer, sub: subject
}

func ExampleJSONWebToken_Claims_multiple() {
	raw := `eyJhbGciOiJIUzI1NiJ9.eyJTY29wZXMiOlsiZm9vIiwiYmFyIl0sImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QifQ.esKOIsmwkudr_gnfnB4SngxIr-7pspd5XzG3PImfQ6Y`
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		panic(err)
	}

	out := jwt.Claims{}
	out2 := struct {
		Scopes []string
	}{}
	if err := tok.Claims(sharedKey, &out, &out2); err != nil {
		panic(err)
	}
	fmt.Printf("iss: %s, sub: %s, scopes: %s\n", out.Issuer, out.Subject, strings.Join(out2.Scopes, ","))
	// Output: iss: issuer, sub: subject, scopes: foo,bar
}
