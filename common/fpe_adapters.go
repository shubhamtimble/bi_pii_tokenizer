// common/fpe_adapters.go
package common

import (
	"fmt"
	"strings"

	"github.com/capitalone/fpe/ff1"
)

// ff1EncryptGeneric implements FF1 encryption using CapitalOne's go library.
// - key: raw AES key bytes (16/24/32 bytes typically)
// - radix: numeric radix (10 for digits, 26 for letters, etc.)
// - tweak: optional tweak bytes (may be nil)
// - plaintext: []int values 0..radix-1
// returns ciphertext as []int
func ff1EncryptGeneric(key []byte, radix int, tweak []byte, plaintext []int) ([]int, error) {
	// We will use a lowercase alphabet for the ff1 cipher (library expects lower-case alphabet)
	alphabet, err := alphabetForRadix(radix, false) // always get lowercase alphabet for cipher operations
	if err != nil {
		return nil, err
	}

	// convert plaintext ints -> string using lowercase alphabet
	plainStr, err := intsToStringWithAlphabet(plaintext, alphabet)
	if err != nil {
		return nil, err
	}

	// Ensure string is lowercase (defensive)
	plainStr = strings.ToLower(plainStr)

	// Create ff1 cipher. maxTlen equals tweak length (0 allowed)
	maxTlen := 0
	if tweak != nil {
		maxTlen = len(tweak)
	}
	c, err := ff1.NewCipher(radix, maxTlen, key, tweak)
	if err != nil {
		return nil, fmt.Errorf("ff1 NewCipher error: %w", err)
	}

	// Encrypt using the lowercase alphabet / plaintext
	cipherStr, err := c.EncryptWithTweak(plainStr, tweak)
	if err != nil {
		// helpful debug: surface the plainStr and expected alphabet
		return nil, fmt.Errorf("ff1 EncryptWithTweak error: %w (plain=%q alphabet=%q)", err, plainStr, alphabet)
	}

	// map cipher string back to []int according to the same lowercase alphabet
	out, err := stringToIntsWithAlphabet(cipherStr, alphabet)
	if err != nil {
		return nil, fmt.Errorf("ff1: stringToIntsWithAlphabet: %w", err)
	}
	return out, nil
}

// alphabetForRadix returns an alphabet string for a given radix.
// If alphaUpper==true and radix==26 it returns "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
// For radix <=10 returns "0123456789"[:radix].
// For radix>10 (and alphaUpper==false) returns "0123456789abcdefghijklmnopqrstuvwxyz"[:radix].
func alphabetForRadix(radix int, alphaUpper bool) (string, error) {
	if radix < 2 || radix > 36 {
		return "", fmt.Errorf("unsupported radix %d (must be 2..36)", radix)
	}
	if radix <= 10 {
		base := "0123456789"
		return base[:radix], nil
	}
	if alphaUpper && radix == 26 {
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZ", nil
	}
	base := "0123456789abcdefghijklmnopqrstuvwxyz"
	return base[:radix], nil
}
