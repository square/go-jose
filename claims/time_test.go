package claims

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var fixedNow = func() time.Time {
	return unix(1000)
}

func unix(u int) time.Time {
	return time.Unix(int64(u), 0)
}

func TestDefaultTimeSource(t *testing.T) {

	assert := assert.New(t)

	assert.Equal(time.Now().Unix(), defaultTimeSource().Unix())

}

func TestExpires(t *testing.T) {

	assert := assert.New(t)

	f := func(claim int) (Claims, error) {

		var (
			c = NewClaims().Expires(unix(claim))
			v = NewVerifier().Add(Expires, Time{fixedNow})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f(100)

	assert.Nil(c)
	assert.EqualError(e, "violating expires at 100, now it's 1000")

	c, e = f(1000)

	assert.Nil(c)
	assert.EqualError(e, "violating expires at 1000, now it's 1000")

	c, e = f(1001)

	assert.Equal(map[Claim]interface{}{"exp": 1001}, map[Claim]interface{}(c))
	assert.NoError(e)

}

func TestNotBefore(t *testing.T) {

	assert := assert.New(t)

	f := func(claim int) (Claims, error) {

		var (
			c = NewClaims().NotBefore(unix(claim))
			v = NewVerifier().Add(NotBefore, Time{fixedNow})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f(100)

	assert.Equal(map[Claim]interface{}{"nbf": 100}, map[Claim]interface{}(c))
	assert.NoError(e)

	c, e = f(1000)

	assert.Equal(map[Claim]interface{}{"nbf": 1000}, map[Claim]interface{}(c))
	assert.NoError(e)

	c, e = f(1001)

	assert.Nil(c)
	assert.EqualError(e, "violating not before 1001, now it's 1000")

}

func TestIssuedAt(t *testing.T) {

	assert := assert.New(t)

	f := func(claim int) (Claims, error) {

		var (
			c = NewClaims().IssuedAt(unix(claim))
			v = NewVerifier().Add(IssuedAt, Time{fixedNow})
		)

		return v.DeserializeAndVerify(c.Bytes())

	}

	c, e := f(100)

	assert.Equal(map[Claim]interface{}{"iat": 100}, map[Claim]interface{}(c))
	assert.NoError(e)

	c, e = f(1000)

	assert.Equal(map[Claim]interface{}{"iat": 1000}, map[Claim]interface{}(c))
	assert.NoError(e)

	c, e = f(1001)

	assert.Nil(c)
	assert.EqualError(e, "violating issued at 1001, now it's 1000 (clocks or timezone settings might be off)")

}
