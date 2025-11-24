// common/pii_spec.go
package common

import (
	"errors"
	"strings"
)

// Segment describes a piece of a PII value.
type Segment struct {
	Name     string // descriptive
	FixedLen int    // >0 for fixed; 0 for variable
	Alphabet string // explicit alphabet (if empty, Radix may be used)
	Radix    int
	Preserve bool // true => preserve as-is
}

// PiiSpec describes PII type segmentation and preprocess/postprocess hooks.
type PiiSpec struct {
	TypeName    string
	Segments    []Segment
	Preprocess  func(string) (string, error)
	Postprocess func(string) (string, error)
}

var (
	ErrSpecMissing = errors.New("pii spec missing")
	piiRegistry    = map[string]PiiSpec{}
)

// RegisterSpec registers or overwrites a PII spec.
func RegisterSpec(spec PiiSpec) {
	piiRegistry[strings.ToUpper(spec.TypeName)] = spec
}

// GetSpec returns the registered spec by type name (case-insensitive).
func GetSpec(typeName string) (PiiSpec, error) {
	if spec, ok := piiRegistry[strings.ToUpper(typeName)]; ok {
		return spec, nil
	}
	return PiiSpec{}, ErrSpecMissing
}
