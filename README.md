# Go JOSE 

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/square/go-jose) [![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/go-jose/master/LICENSE) [![build](https://img.shields.io/travis/square/go-jose.svg?style=flat)](https://travis-ci.org/square/go-jose) [![coverage](https://img.shields.io/coveralls/square/go-jose.svg?style=flat)](https://coveralls.io/r/square/go-jose)

Package jose aims to provide an implementation of the Javascript Object Signing
and Encryption set of standards. For the moment, it mainly focuses on encryption
and signing based on the JSON Web Encryption and JSON Web Signature standards.

**Disclaimer**: This library contains encryption software that is subject to
the U.S. Export Administration Regulations. You may not export, re-export,
transfer or download this code or any part of it in violation of any United
States law, directive or regulation. In particular this software may not be
exported or re-exported in any form or on any media to Iran, North Sudan,
Syria, Cuba, or North Korea, or to denied persons or entities mentioned on any
US maintained blocked list.

## Overview

The implementation follows the
[JSON Web Encryption](http://www.ietf.org/id/draft-ietf-jose-json-web-encryption-37.txt) and
[JSON Web Signature](http://www.ietf.org/id/draft-ietf-jose-json-web-signature-37.txt)
standard drafts as of version 37. Tables of supported algorithms are shown
below. The library supports both the compact and full serialization formats,
and has optional support for multiple recipients. It also comes with a small
command-line utility (`jose-util`) for encrypting/decrypting JWE messages in
a shell.

### Supported algorithms

 Key encryption             | Algorithm identifier(s)
 :------------------------- | :------------------------------
 RSA-PKCS#1v1.5             | RSA1_5
 RSA-OAEP                   | RSA-OAEP, RSA-OAEP-256
 AES key wrap               | A128KW, A192KW, A256KW
 AES-GCM key wrap           | A128GCMKW, A192GCMKW, A256GCMKW
 ECDH-ES + AES key wrap     | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
 ECDH-ES (direct)           | ECDH-ES<sup>1</sup>
 Direct encryption          | dir<sup>1</sup>

<sup>1. Not supported in multi-recipient mode</sup>

 Signing / MAC              | Algorithm identifier(s)
 :------------------------- | :------------------------------
 RSASSA-PKCS#1v1.5          | RS256, RS384, RS512
 RSASSA-PSS                 | PS256, PS384, PS512
 HMAC                       | HS256, HS384, HS512
 ECDSA                      | ES256, ES384, ES512

 Content encryption         | Algorithm identifier(s)
 :------------------------- | :------------------------------
 AES-CBC+HMAC               | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
 AES-GCM                    | A128GCM, A192GCM, A256GCM 

 Compression                | Algorithm identifiers(s)
 :------------------------- | -------------------------------
 DEFLATE (RFC 1951)         | DEF

## Examples

Encryption/decryption example using RSA:

```Go
// Generate a public/private key pair to use for this example. The library
// also provides two utility functions (LoadPublicKey and LoadPrivateKey)
// that can be used to load keys from PEM/DER-encoded data.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
  panic(err)
}

// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
// indicate that the selected algorithm(s) are not currently supported.
publicKey := &privateKey.PublicKey
encrypter, err := NewEncrypter(RSA_OAEP, A128GCM, publicKey)
if err != nil {
  panic(err)
}

// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
// JWE object, which can then be serialized for output afterwards. An error
// would indicate a problem in an underlying cryptographic primitive.
var plaintext = []byte("Lorem ipsum dolor sit amet")
object, err := encrypter.Encrypt(plaintext)
if err != nil {
  panic(err)
}

// Serialize the encrypted object using the full serialization format.
// Alternatively you can also use the compact format here by calling
// object.CompactSerialize() instead.
serialized, err := object.FullSerialize()

// Now let's instantiate a decrypter so we can get back the plaintext.
decrypter, err := NewDecrypter(privateKey)
if err != nil {
  panic(err)
}

// Parse the serialized, encrypted JWE object. An error would indicate that
// the given input did not represent a valid message.
object, err = Parse(serialized)
if err != nil {
  panic(err)
}

// Now we can decrypt and get back our original plaintext. An error here
// would indicate the the message failed to decrypt, e.g. because the auth
// tag was broken and the message was tampered with.
decrypted, err := decrypter.Decrypt(object)
if err != nil {
  panic(err)
}

fmt.Printf(string(decrypted))
// output: Lorem ipsum dolor sit amet
```

Signing/verification example using RSA:

```Go
// Generate a public/private key pair to use for this example. The library
// also provides two utility functions (LoadPublicKey and LoadPrivateKey)
// that can be used to load keys from PEM/DER-encoded data.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	panic(err)
}

// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
signer, err := NewSigner(PS512, privateKey)
if err != nil {
	panic(err)
}

// Sign a sample payload. Calling the signer returns a protected JWS object,
// which can then be serialized for output afterwards. An error would
// indicate a problem in an underlying cryptographic primitive.
var payload = []byte("Lorem ipsum dolor sit amet")
object, err := signer.Sign(payload)
if err != nil {
	panic(err)
}

// Serialize the encrypted object using the full serialization format.
// Alternatively you can also use the compact format here by calling
// object.CompactSerialize() instead.
serialized := object.FullSerialize()

// Parse the serialized, protected JWS object. An error would indicate that
// the given input did not represent a valid message.
object, err = ParseSigned(serialized)
if err != nil {
	panic(err)
}

// Now we can verify the signature on the payload. An error here would
// indicate the the message failed to verify, e.g. because the signature was
// broken or the message was tampered with.
output, err := object.Verify(&privateKey.PublicKey)
if err != nil {
	panic(err)
}

fmt.Printf(string(output))
// output: Lorem ipsum dolor sit amet
```

More examples can be found in the [Godoc
reference](https://godoc.org/github.com/square/go-jose) for this package. The
`jose-util` subdirectory also contains a small command-line utility for
encrypting/decrypting JWE messages which might be useful as an example.
