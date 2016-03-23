package validator

import (
	"time"

	"github.com/square/go-jose/jwt"
)

const (
	DefaultExpLeeway = 1.0 * time.Minute
	DefaultNbfLeeway = 1.0 * time.Minute
	NoLeeway         = -1
)

type Validator struct {
	p Params
}

type Params struct {
	Issuer      string
	Subject     string
	Audience    []string
	ID          string
	MinIssuedAt time.Time
	ExpLeeway   time.Duration
	NbfLeeway   time.Duration
}

func New(p Params) *Validator {
	if p.ExpLeeway == 0 {
		p.ExpLeeway = DefaultExpLeeway
	}

	if p.NbfLeeway == 0 {
		p.NbfLeeway = DefaultNbfLeeway
	}

	if p.ExpLeeway == NoLeeway {
		p.ExpLeeway = 0
	}

	if p.NbfLeeway == 0 {
		p.NbfLeeway = 0
	}

	return &Validator{p}
}

func (v *Validator) Validate(c jwt.Claims, now time.Time) error {
	e := &v.p
	if e.Issuer != "" && e.Issuer != c.Issuer {
		return ErrInvalidIssuer
	}

	if e.Subject != "" && e.Subject != c.Subject {
		return ErrInvalidSubject
	}

	if e.ID != "" && e.ID != c.ID {
		return ErrInvalidID
	}

	if len(e.Audience) != 0 {
		if len(e.Audience) != len(c.Audience) {
			return ErrInvalidAudience
		}

		for i, a := range e.Audience {
			if a != c.Audience[i] {
				return ErrInvalidAudience
			}
		}
	}

	if e.MinIssuedAt.After(e.MinIssuedAt) {
		return ErrInvalidIssuedAt
	}

	if now.Add(-e.NbfLeeway).Before(c.NotBefore) {
		return ErrInvalidNotBefore
	}

	if now.Add(e.ExpLeeway).After(c.Expiry) {
		return ErrInvalidExpiry
	}

	return nil
}
