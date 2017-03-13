package claims

import (
	"fmt"
	"time"
)

// TimeSource defines a source for the current time
type TimeSource func() time.Time

func defaultTimeSource() time.Time {
	return time.Now()
}

// Time handles time related registered claim verification, using an optional
// TimeSource as point of reference
type Time struct {
	T TimeSource
}

// Verify implements the Assertion interface
func (t Time) Verify(claim Claim, value interface{}) error {

	const (
		errExp = "violating expires at %d, now it's %d"
		errIat = "violating issued at %d, now it's %d (clocks or timezone settings might be off)"
		errNbf = "violating not before %d, now it's %d"
	)

	var ts = t.T

	if ts == nil {
		ts = defaultTimeSource
	}

	switch v := (value).(type) {
	case int:

		var now = int(ts().UTC().Unix())

		switch claim {
		case Expires:

			if now >= v {
				return fmt.Errorf(errExp, v, now)
			}

		case NotBefore:

			if now < v {
				return fmt.Errorf(errNbf, v, now)
			}

		case IssuedAt:

			if v > now {
				return fmt.Errorf(errIat, v, now)
			}

		}

	}

	return nil

}
