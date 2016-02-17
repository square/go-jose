package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEquals(t *testing.T) {

	assert := assert.New(t)

	f := func(claim Claim, value interface{}, want interface{}) (Claims, error) {

		var (
			c = NewClaims().Add(claim, value)
			v = NewVerifier().Add(claim, Equals{want})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f("foo", "bar", "bar")

	assert.Equal(map[Claim]interface{}{"foo": "bar"}, map[Claim]interface{}(c))
	assert.NoError(e)

	c, e = f("foo", "bar", "wee")

	assert.Nil(c)
	assert.EqualError(e, `value is not equal: want "wee", got "bar"`)

	c, e = f("foo", nil, "bar")

	assert.Nil(c)
	assert.EqualError(e, `value is not equal: want "bar", got "<nil>"`)

	c, e = f("foo", "bar", nil)

	assert.Nil(c)
	assert.EqualError(e, `value is not equal: want "<nil>", got "bar"`)

}
