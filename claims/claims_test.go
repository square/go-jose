package claims

import (
	"testing"
	"time"

	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
)

func TestClaims(t *testing.T) {

	const (
		key     = "open sesame"
		subject = "4e8221ad-2f11-4a12-8d75-aca4219bae3f"
	)

	assert := assert.New(t)

	signer, err := jose.NewSigner(jose.HS256, []byte(key))

	if err != nil {
		assert.NoError(err)
	}

	var (
		newClaims Claims
		now       = time.Now().UTC()
		oldClaims = NewClaims()
	)

	oldClaims.Add(Subject, subject)
	oldClaims.Expires(now.Add(10 * time.Second))
	oldClaims.IssuedAt(now)
	oldClaims.NotBefore(now)

	object, err := signer.Sign(oldClaims.Bytes())

	assert.NoError(err)

	serialized, err := object.CompactSerialize()

	assert.NoError(err)

	deserialized, err := jose.ParseSigned(serialized)

	output, err := deserialized.Verify([]byte(key))

	assert.NoError(err)

	var verifier = NewVerifier()

	verifier.Add(Expires, Time{})
	verifier.Add(IssuedAt, Time{})
	verifier.Add(NotBefore, Time{})
	verifier.Add(Subject, Equals{subject})

	newClaims, err = verifier.DeserializeAndVerify(output)

	assert.NoError(err)

	assert.Equal(oldClaims, newClaims)

}

func TestClaimsMarshallingPanic(t *testing.T) {

	assert := assert.New(t)

	c := NewClaims().Add("illegal-value", make(chan struct{}))

	out, err := c.MarshalBinary()

	assert.Nil(out)
	assert.Error(err)

	assert.Panics(func() {
		c.Bytes()
	})

}
