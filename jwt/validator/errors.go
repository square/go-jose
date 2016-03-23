package validator

import "errors"

var ErrInvalidIssuer = errors.New("JWT: invalid issuer")
var ErrInvalidSubject = errors.New("JWT: invalid subject")
var ErrInvalidAudience = errors.New("JWT: invalid audience")
var ErrInvalidID = errors.New("JWT: invalid ID")
var ErrInvalidIssuedAt = errors.New("JWT: token issued before minimum issue date")
var ErrInvalidNotBefore = errors.New("JWT: token used before its valid date in claim <nbf>")
var ErrInvalidExpiry = errors.New("JWT: token used after its valid date in claim <exp>")
