// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

var (
	// ErrEmptyINP is an error representing an INP that is empty, which means it is
	// missing both a `spec` and `specs` (both are nil).
	ErrEmptyINP = NewErrParse("Invalid IsovalentNetworkPolicy spec(s): empty policy")

	// ErrEmptyICNP is an error representing an ICNP that is empty, which means it is
	// missing both a `spec` and `specs` (both are nil).
	ErrEmptyICNP = NewErrParse("Invalid IsovalentClusterwideNetworkPolicy spec(s): empty policy")

	// ParsingErr is for comparison when checking error types.
	ParsingErr = NewErrParse("")
)

// ErrParse is an error to describe where policy fails to parse due any invalid
// rule.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type ErrParse struct {
	msg string
}

// NewErrParse returns a new ErrParse.
func NewErrParse(msg string) ErrParse {
	return ErrParse{
		msg: msg,
	}
}

// Error returns the error message for parsing
func (e ErrParse) Error() string {
	return e.msg
}

// Is returns true if the given error is the type of 'ErrParse'.
func (_ ErrParse) Is(e error) bool {
	_, ok := e.(ErrParse)
	return ok
}
