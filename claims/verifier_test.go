package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBrokenJson(t *testing.T) {

	assert := assert.New(t)

	c, e := NewVerifier().DeserializeAndVerify(nil)

	assert.Nil(c)
	assert.Error(e)

}

func TestMissingClaim(t *testing.T) {

	assert := assert.New(t)

	f := func() (Claims, error) {

		var (
			c = NewClaims().Add("foo", "bar")
			v = NewVerifier().Add(Expires, Time{fixedNow})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f()

	assert.Nil(c)
	assert.EqualError(e, `assertion requested for non-existing claim "exp"`)

}

func TestTypeError(t *testing.T) {

	assert := assert.New(t)

	f := func() (Claims, error) {

		var (
			c = NewClaims().Add(Expires, "bar")
			v = NewVerifier().Add(Expires, Time{fixedNow})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f()

	assert.Nil(c)
	assert.EqualError(e, `unsupported type "string" of claim's "exp" value of "bar"`)

}
