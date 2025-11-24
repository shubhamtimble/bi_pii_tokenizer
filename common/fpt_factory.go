// common/fpt_factory.go
package common

import (
    "encoding/base64"
    "fmt"
    "os"
)

// NewFPTGeneratorFromEnv builds an FPTGenerator based on env var FPT_MODE.
// FPT_MODE: "current" (default), "ff1", "ff3"
// For ff1/ff3, FPE_KEY_BASE64 must be present.
func NewFPTGeneratorFromEnv() (FPTGenerator, error) {
    mode := os.Getenv("FPT_MODE")
    if mode == "" {
        mode = "current"
    }
    switch mode {
    case "current":
        return &CurrentGenerator{}, nil
    case "ff1":
        kb64 := os.Getenv("FPE_KEY_BASE64")
        if kb64 == "" {
            return nil, fmt.Errorf("FPT_MODE=ff1 but FPE_KEY_BASE64 not set")
        }
        key, err := base64.StdEncoding.DecodeString(kb64)
        if err != nil {
            return nil, fmt.Errorf("invalid FPE_KEY_BASE64: %w", err)
        }
        kv := os.Getenv("FPE_KEY_VERSION")
        if kv == "" {
            kv = "1"
        }
        return NewFF1Generator(key, kv)
    default:
        return nil, fmt.Errorf("unsupported FPT_MODE: %s", mode)
    }
}
