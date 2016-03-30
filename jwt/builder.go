package jwt

import (
	"reflect"

	"github.com/square/go-jose"
)

// Builder is an utility for making JSON Web Tokens
// Calls can be chained and the errors are accumulated till final call to
// CompactSerialize/FullSerialize allowing for single-line token creation
// Builder is immutable therefore it can be safely reused once created
type Builder struct {
	transform  func([]byte) (serializer, error)
	serializer serializer
	err        error
}

type serializer interface {
	FullSerialize() string
	CompactSerialize() (string, error)
}

// New creates builder using provided Signer/Encrypter
func New(t interface{}) *Builder {
	switch t := t.(type) {
	case jose.Signer:
		return &Builder{
			transform: func(b []byte) (serializer, error) {
				return t.Sign(b)
			},
		}
	case jose.Encrypter:
		return &Builder{
			transform: func(b []byte) (serializer, error) {
				return t.Encrypt(b)
			},
		}
	default:
		panic("Expected Signer or Encrypter argument")
	}
}

// Claims encodes claims into JWE/JWS form
func (b *Builder) Claims(c interface{}) *Builder {
	if b.transform == nil {
		panic("Signer/Encrypter not set")
	}

	r := *b

	t := reflect.TypeOf(c)
	if t.Kind() != reflect.Map && (t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct) {
		r.err = ErrInvalidClaims
		return &r
	}

	raw, err := marshalClaims(c)
	if err != nil {
		r.err = err
		return &r
	}

	r.serializer, r.err = r.transform(raw)
	return &r
}

// FullSerialize serializes an token using the full JSON serialization format
func (b *Builder) FullSerialize() (string, error) {
	if b.err != nil {
		return "", b.err
	}

	if b.serializer == nil {
		panic("Claims not set")
	}

	return b.serializer.FullSerialize(), nil
}

// CompactSerialize serializes an token using the compact serialization format
func (b *Builder) CompactSerialize() (string, error) {
	if b.err != nil {
		return "", b.err
	}

	if b.serializer == nil {
		panic("Claims not set")
	}

	return b.serializer.CompactSerialize()
}
