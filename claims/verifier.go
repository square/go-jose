package claims

import (
	"encoding/json"
	"fmt"
)

// Verifier bundles a number Assertions
type Verifier struct {
	Assertions Assertions
}

// NewVerifier initializes a new verifier
func NewVerifier() *Verifier {

	return &Verifier{
		Assertions: make(map[Claim][]Assertion),
	}

}

// Add adds an Assertion for a given Claim
func (v *Verifier) Add(c Claim, a Assertion) *Verifier {
	v.Assertions[c] = append(v.Assertions[c], a)
	return v
}

// DeserializeAndVerify deserializes the given token and applies all previously
// declared Assertions
func (v *Verifier) DeserializeAndVerify(token []byte) (Claims, error) {

	var c = NewClaims()

	if err := json.Unmarshal(token, &c); err != nil {
		return nil, err
	}

	return v.Verify(c)

}

// Verify applies all previously declared Assertions to the given Claims
func (v *Verifier) Verify(c Claims) (Claims, error) {

	const (
		errMissingClaim = `assertion requested for non-existing claim %q`
		errValueType    = `unsupported type "%T" of claim's %q value of "%v"`
	)

	for ck, a := range v.Assertions {

		// if there is no matching claim for the given assertion, raise an error
		if _, ok := c[ck]; !ok {
			return nil, fmt.Errorf(errMissingClaim, ck)
		}

		// cast certain well-known claim values to int
		switch ck {
		case Expires, NotBefore, IssuedAt:

			switch v := c[ck].(type) {

			case float64:
				c[ck] = int(v)
			default:
				return nil, fmt.Errorf(errValueType, v, ck, v)
			}

		}

		for _, e := range a {

			if err := e.Verify(ck, c[ck]); err != nil {
				return nil, err
			}

		}

	}

	return c, nil

}
