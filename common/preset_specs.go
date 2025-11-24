// common/preset_specs.go
package common

import (
	"errors"
	"strings"
)

func init() {
	// PAN: fixed 10 chars: 5 letters, 4 digits, 1 letter
	RegisterSpec(PiiSpec{
		TypeName: "PAN",
		Preprocess: func(s string) (string, error) {
			return strings.ToUpper(strings.TrimSpace(s)), nil
		},
		Segments: []Segment{
			{Name: "pan_letters1", FixedLen: 5, Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
			{Name: "pan_digits", FixedLen: 4, Alphabet: "0123456789"},
			{Name: "pan_letter2", FixedLen: 1, Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		},
	})

	// AADHAR: 12 digits
	RegisterSpec(PiiSpec{
		TypeName: "AADHAR",
		Preprocess: func(s string) (string, error) {
			return strings.TrimSpace(s), nil
		},
		Segments: []Segment{
			{Name: "aadhar_digits", FixedLen: 12, Alphabet: "0123456789"},
		},
	})

	// MOBILE: example 10-digit Indian mobile
	RegisterSpec(PiiSpec{
		TypeName: "MOBILE",
		Preprocess: func(s string) (string, error) {
			s = strings.TrimSpace(s)
			s = strings.TrimPrefix(s, "+91")
			s = strings.ReplaceAll(s, " ", "")
			if len(s) != 10 {
				return "", errors.New("invalid mobile length")
			}
			return s, nil
		},
		Segments: []Segment{
			{Name: "mobile_digits", FixedLen: 10, Alphabet: "0123456789"},
		},
	})

	// EMAIL: preserve domain, FPE on local-part with limited alphabet
	RegisterSpec(PiiSpec{
		TypeName: "EMAIL",
		Preprocess: func(s string) (string, error) {
			return strings.TrimSpace(s), nil
		},
		Segments: []Segment{
			{Name: "localpart", FixedLen: 0, Alphabet: "abcdefghijklmnopqrstuvwxyz0123456789._%+-"},
			{Name: "at", FixedLen: 1, Alphabet: "@", Preserve: true},
			{Name: "domain", FixedLen: 0, Preserve: true},
		},
	})

	// DL: conservative alnum spec
	RegisterSpec(PiiSpec{
		TypeName: "DL",
		Preprocess: func(s string) (string, error) {
			s = strings.ToUpper(strings.TrimSpace(s))
			s = strings.ReplaceAll(s, " ", "")
			if len(s) == 0 {
				return "", errors.New("empty dl")
			}
			return s, nil
		},
		Segments: []Segment{
			{Name: "dl_all", FixedLen: 0, Alphabet: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		},
	})
}
