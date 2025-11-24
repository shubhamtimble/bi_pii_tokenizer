// common/ff1_generator.go
package common

import (
	"context"
	"fmt"
	"strings"
)

// NewFF1Generator creates an FF1 generator instance with raw key bytes and a version string.
func NewFF1Generator(key []byte, keyVersion string) (FPTGenerator, error) {
	return &FF1Generator{key: key, keyVersion: keyVersion}, nil
}

type FF1Generator struct {
	key        []byte
	keyVersion string
}

func (g *FF1Generator) Mode() string { return "ff1" }

func (g *FF1Generator) GeneratePan(ctx context.Context, pan string, tweak []byte) (string, error) {
	return g.GenerateToken(ctx, "PAN", pan, tweak)
}

func (g *FF1Generator) GenerateDigits(ctx context.Context, digits string, tweak []byte) (string, error) {
	return g.GenerateToken(ctx, "AADHAR", digits, tweak)
}

// GenerateToken uses the spec registry (PiiSpec) if available; if not, falls back to simple PAN/AADHAR handlers.
// This implementation supports PAN (segmented) and generic segments.
func (g *FF1Generator) GenerateToken(ctx context.Context, dataType string, normalized string, tweak []byte) (string, error) {
	typ := strings.ToUpper(dataType)

	// If spec exists, use it
	spec, specErr := GetSpec(typ)
	if specErr == nil {
		// optional preprocess
		if spec.Preprocess != nil {
			n, err := spec.Preprocess(normalized)
			if err != nil {
				return "", err
			}
			normalized = n
		}
		// default tweak if empty
		if len(tweak) == 0 {
			tweak = []byte(fmt.Sprintf("%s:%s", spec.TypeName, g.keyVersion))
		}

		// handle EMAIL specially (local@domain)
		if typ == "EMAIL" {
			parts := strings.SplitN(normalized, "@", 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("invalid email format")
			}
			local, domain := parts[0], parts[1]
			// validate allowed alphabet
			localAlpha := spec.Segments[0].Alphabet
			_, err := stringToIntsWithAlphabet(local, localAlpha)
			if err != nil {
				// fallback deterministic base36 mapping using HMAC of local with FPE key
				fallback, ferr := deterministicBase36FromHexWithCounter(commonHMACBytesToHex(g.key, local), len(local), 0)
				if ferr != nil {
					return "", ferr
				}
				return fallback + "@" + domain, nil
			}
			// encrypt local part
			plainInts, _ := stringToIntsWithAlphabet(local, localAlpha)
			cipherInts, err := ff1EncryptGeneric(g.key, len(localAlpha), tweak, plainInts)
			if err != nil {
				return "", err
			}
			cipherLocal, err := intsToStringWithAlphabet(cipherInts, localAlpha)
			if err != nil {
				return "", err
			}
			return cipherLocal + "@" + domain, nil
		}

		// Generic sequential segments
		out := ""
		cursor := 0
		for _, seg := range spec.Segments {
			if seg.Preserve {
				// preserve substring
				if seg.FixedLen > 0 {
					if cursor+seg.FixedLen > len(normalized) {
						return "", fmt.Errorf("invalid length for preserve segment %s", seg.Name)
					}
					out += normalized[cursor : cursor+seg.FixedLen]
					cursor += seg.FixedLen
				} else {
					out += normalized[cursor:]
					cursor = len(normalized)
				}
				continue
			}

			// determine part
			var part string
			if seg.FixedLen > 0 {
				if cursor+seg.FixedLen > len(normalized) {
					return "", fmt.Errorf("invalid length for segment %s", seg.Name)
				}
				part = normalized[cursor : cursor+seg.FixedLen]
				cursor += seg.FixedLen
			} else {
				part = normalized[cursor:]
				cursor = len(normalized)
			}

			alphabet := seg.Alphabet
			if alphabet == "" && seg.Radix > 0 {
				alphabet = defaultAlphabetForRadix(seg.Radix)
			}
			if alphabet == "" {
				return "", fmt.Errorf("no alphabet for segment %s", seg.Name)
			}
			plainInts, err := stringToIntsWithAlphabet(part, alphabet)
			if err != nil {
				// fallback deterministic mapping
				fallback, ferr := deterministicBase36FromHexWithCounter(commonHMACBytesToHex(g.key, part), len(part), 0)
				if ferr != nil {
					return "", ferr
				}
				out += fallback
				continue
			}
			cipherInts, err := ff1EncryptGeneric(g.key, len(alphabet), tweak, plainInts)
			if err != nil {
				return "", err
			}
			cipherPart, err := intsToStringWithAlphabet(cipherInts, alphabet)
			if err != nil {
				return "", err
			}
			out += cipherPart
		}
		if spec.Postprocess != nil {
			return spec.Postprocess(out)
		}
		return out, nil
	}

	// No spec defined: fallback to built-in PAN/AADHAR behaviours
	switch typ {
	// inside FF1Generator.GenerateToken, replace the PAN case with this:

case "PAN":
    // Expect normalized to be 10 chars: 5 letters, 4 digits, 1 letter
    if len(normalized) != 10 {
        return "", fmt.Errorf("invalid PAN length")
    }
    // build tweak if empty
    if len(tweak) == 0 {
        tweak = []byte(fmt.Sprintf("PAN:%s", g.keyVersion))
    }

    // - Create a 6-letter block: first 5 letters + last letter (positions 0..4 and 9)
    lettersBlock := normalized[0:5] + normalized[9:10] // length 6
    aPlain := alphaToInts(lettersBlock)                 // 6 ints (0..25)

    // - Create the 4-digit middle block (positions 5..8)
    digitsBlock := normalized[5:9]                      // length 4
    bPlain := digitsToInts(digitsBlock)                 // 4 ints (0..9)

    // Encrypt the 6-letter block with radix 26
    aCipher, err := ff1EncryptGeneric(g.key, 26, tweak, aPlain)
    if err != nil {
        return "", err
    }
    // Encrypt the 4-digit block with radix 10
    bCipher, err := ff1EncryptGeneric(g.key, 10, tweak, bPlain)
    if err != nil {
        return "", err
    }

    // Reassemble into PAN format: first 5 from aCipher[0:5], digits from bCipher, last letter from aCipher[5]
    out := make([]byte, 10)
    // aCipher -> intsToAlpha returns uppercase letters
    copy(out[0:5], intsToAlpha(aCipher[0:5]))
    copy(out[5:9], intsToDigits(bCipher))
    copy(out[9:10], intsToAlpha([]int{aCipher[5]}))

    return string(out), nil


	case "AADHAR":
		// digits-only
		L := len(normalized)
		if L <= 0 {
			return "", fmt.Errorf("invalid aadhar length")
		}
		if len(tweak) == 0 {
			tweak = []byte(fmt.Sprintf("AADHAR:%s", g.keyVersion))
		}
		plain := digitsToInts(normalized)
		cipherInts, err := ff1EncryptGeneric(g.key, 10, tweak, plain)
		if err != nil {
			return "", err
		}
		return string(intsToDigits(cipherInts)), nil

	default:
		return "", fmt.Errorf("unsupported data type for ff1: %s", dataType)
	}
}
