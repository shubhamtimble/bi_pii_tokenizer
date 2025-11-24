// common/fpt.go
package common

import "context"

type FPTGenerator interface {
    Mode() string
    // GenerateToken will generate a format-preserving token for given dataType and normalized value.
    // The generator will use PiiSpec from registry to split into segments internally.
    GenerateToken(ctx context.Context, dataType string, normalized string, tweak []byte) (string, error)

    // Deprecated compatibility functions kept if needed:
    GeneratePan(ctx context.Context, pan string, tweak []byte) (string, error)
    GenerateDigits(ctx context.Context, digits string, tweak []byte) (string, error)
}
