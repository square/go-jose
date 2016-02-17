package claims

import (
	"fmt"
	"reflect"
)

// Equals enforces deep equality of the claim value to a given value
type Equals struct {
	Value interface{}
}

// Verify implements the Assertion interface
func (e Equals) Verify(claim Claim, value interface{}) error {

	if !reflect.DeepEqual(e.Value, value) {
		return fmt.Errorf(`value is not equal: want "%v", got "%v"`, e.Value, value)
	}

	return nil

}
