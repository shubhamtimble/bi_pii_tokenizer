// common/current_generator.go
package common

import (
    "context"
    "fmt"
    "strings"
)

type CurrentGenerator struct{}

func (c *CurrentGenerator) Mode() string { return "current" }

func (c *CurrentGenerator) GeneratePan(ctx context.Context, pan string, tweak []byte) (string, error) {
    if len(tweak) == 0 {
        return "", fmt.Errorf("current generator requires blindHex in tweak")
    }
    blindHex := string(tweak)
    return FPTFromBlindIndexWithCounter(blindHex, pan, "PAN", 0)
}
func (c *CurrentGenerator) GenerateDigits(ctx context.Context, digits string, tweak []byte) (string, error) {
    if len(tweak) == 0 {
        return "", fmt.Errorf("current generator requires blindHex in tweak")
    }
    blindHex := string(tweak)
    return fptDigitsFromBlind(blindHex, len(digits), 0)
}

// GenerateToken splits normalized value based on the PII spec and uses the legacy current method per segment.
// For current generator we pass blindHex (from tweak) into per-segment hashing (so we still produce deterministic tokens).
func (c *CurrentGenerator) GenerateToken(ctx context.Context, dataType string, normalized string, tweak []byte) (string, error) {
    // tweak expected to include blindHex for current mode
    if len(tweak) == 0 {
        return "", fmt.Errorf("current generator requires blindHex in tweak")
    }
    blindHex := string(tweak)

    spec, err := GetSpec(strings.ToUpper(dataType))
    if err != nil {
        return "", err
    }

    // For simple fixed-length segments we call existing fpt functions.
    // For variable length segments (like email localpart) we call fptDigitsFromBlind or fallback: use deterministicBase36...
    // Naive approach: we will iterate segments and for each produce a token piece by calling the existing helpers
    out := ""
    cursor := 0
    // For EMAIL, special handling: split at '@'
    if strings.ToUpper(dataType) == "EMAIL" {
        // split
        parts := strings.SplitN(normalized, "@", 2)
        if len(parts) != 2 {
            return "", fmt.Errorf("invalid email format")
        }
        local, domain := parts[0], parts[1]
        // check allowed chars for local
        specLocal := spec.Segments[0] // localpart spec
        allowed := specLocal.Alphabet
        for i := 0; i < len(local); i++ {
            if !strings.ContainsRune(allowed, rune(local[i])) {
                // fallback to base36 deterministic mapping using blind+local
                cand, err := deterministicBase36FromHexWithCounter(blindHex+":"+local, len(local), 0)
                if err != nil {
                    return "", err
                }
                return cand + "@" + domain, nil
            }
        }
        // use current generator approach for localpart digits by converting to equivalent numeric string,
        // but for simplicity, call deterministicBase36FromHexWithCounter
        tokenLocal, err := deterministicBase36FromHexWithCounter(blindHex+":"+local, len(local), 0)
        if err != nil {
            return "", err
        }
        return tokenLocal + "@" + domain, nil
    }

    // For generic segments: if fixed-length alpha/digits we reuse existing fpt functions.
    for _, seg := range spec.Segments {
        if seg.Preserve {
            // identify substring from normalized based on remaining length heuristics:
            // If domain (preserve) and dataType==EMAIL we handled above; otherwise try to slice by FixedLen.
            if seg.FixedLen > 0 {
                if cursor+seg.FixedLen > len(normalized) {
                    return "", fmt.Errorf("invalid length for segment %s", seg.Name)
                }
                out += normalized[cursor : cursor+seg.FixedLen]
                cursor += seg.FixedLen
            } else {
                // variable preserve: take rest
                out += normalized[cursor:]
                cursor = len(normalized)
            }
            continue
        }

        if seg.Alphabet == "0123456789" && seg.FixedLen > 0 {
            // digits fixed len
            if cursor+seg.FixedLen > len(normalized) {
                return "", fmt.Errorf("invalid length for segment %s", seg.Name)
            }
            sub := normalized[cursor : cursor+seg.FixedLen]
            tok, err := fptDigitsFromBlind(blindHex, len(sub), 0)
            if err != nil {
                return "", err
            }
            out += tok
            cursor += seg.FixedLen
            continue
        }

        // Fallback: deterministic base36 using blind+substring
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
        tok, err := deterministicBase36FromHexWithCounter(blindHex+":"+part, len(part), 0)
        if err != nil {
            return "", err
        }
        out += tok
    }
    return out, nil
}
