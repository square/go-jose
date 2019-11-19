# JOSE CLI

The `jose-util` command line utility allows for encryption, decryption, signing
and verification of JOSE messages. Its main purpose is to facilitate dealing
with JOSE messages when testing or debugging.

## Installation

```
$ go get -u github.com/square/go-jose/jose-util
$ go install github.com/square/go-jose/jose-util
```

## Usage

The utility includes the subcommands `encrypt`, `decrypt`, `sign`, `verify` and
`expand`. Examples for each command can be found below.

Algorithms are selected via the `--alg` and `--enc` flags, which influence the
`alg` and `enc` headers in respectively. For JWE, `--alg` specifies the key
management algorithm (e.g. `RSA-OAEP`) and `--enc` specifies the content
encryption algorithm (e.g. `A128GCM`). For JWS, `--alg` specifies the
signature algorithm (e.g. `PS256`).

Input and output files can be specified via the `--in` and `--out` flags.
Either flag can be omitted, in which case `jose-util` uses stdin/stdout for
input/output respectively. By default each command will output a compact
message, but it's possible to get the full serialization by supplying the
`--full` flag.

Keys are specified via the `--key` flag. Supported key types are naked RSA/EC
keys and X.509 certificates with embedded RSA/EC keys. Keys must be in PEM,
DER or JWK formats.


## Testing

`cram` is used for testing.  This can be installed with pip or `sudo apt install
python-cram` See the travis file for how this is used in testing. For example,
`go build && PATH=$PWD:$PATH cram -v jose-util.t`


## Examples

### Generate key pair

Generates a key pair, either for signing/verification or encryption/decryption. Generated keys will be written to the current directory.

    # Generate keys for signing (for RSA-PSS)
    jose-util generate-key --use sig --alg RS256

    # Generate keys for signing (for EdDSA)
    jose-util generate-key --use sig --alg EdDSA

    # Generate keys for encryption (for RSA-OAEP)
    jose-util generate-key --use enc --alg RSA-OAEP

    # Generate keys for encryption (for ECDH-ES)
    jose-util generate-key --use enc --alg ECDH-ES+A128KW

### Encrypt

Takes a plaintext as input, encrypts, and prints the encrypted message.

    # From stdin, to stdout
    jose-util encrypt --key public-key.pem --alg RSA-OAEP --enc A128GCM

    # Operating on files
    jose-util encrypt --key public-key.pem --alg RSA-OAEP --enc A128GCM --in plaintext.txt --out ciphertext.txt

### Decrypt

Takes an encrypted message (JWE) as input, decrypts, and prints the plaintext.

    # From stdin, to stdout
    jose-util decrypt --key private-key.pem

    # Operating on files
    jose-util decrypt --key private-key.pem --in ciphertext.txt --out plaintext.txt

### Sign

Takes a payload as input, signs it, and prints the signed message with the embedded payload.

    # From stdin, to stdout
    jose-util sign --key private-key.pem --alg PS256

    # Operating on files
    jose-util sign --key private-key.pem --alg PS256 --in message.txt --out signed-message.txt

### Verify

Reads a signed message (JWS), verifies it, and extracts the payload.

    # From stdin, to stdout
    jose-util verify --key public-key.pem

    # Operating on files
    jose-util verify --key public-key.pem --in signed-message.txt --out message.txt

### Expand

Expands a compact message to the full serialization format.

    jose-util expand --format JWE   # Expands a compact JWE to full format
    jose-util expand --format JWS   # Expands a compact JWS to full format

### Decode base64

The JOSE format uses url-safe base64 in payloads, but the `base64` utility that ships with
most Linux distributions (or macOS) only supports the standard base64 encoding. To make it easier
to deal with these payloads a `b64decode` command is available in `jose-util` that can decode
both regular and url-safe base64 data.

    echo "8J-Ukgo" | jose-util b64decode
