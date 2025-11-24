// common/fpe_helpers.go
package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// alphaToInts maps A..Z -> 0..25
func alphaToInts(s string) []int {
	out := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = int(s[i] - 'A')
	}
	return out
}

// intsToAlpha maps 0..25 -> A..Z
func intsToAlpha(a []int) []byte {
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = byte('A' + a[i])
	}
	return out
}

// digitsToInts maps '0'..'9' -> 0..9
func digitsToInts(s string) []int {
	out := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = int(s[i] - '0')
	}
	return out
}

// intsToDigits maps 0..9 -> '0'..'9'
func intsToDigits(a []int) []byte {
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = byte('0' + a[i])
	}
	return out
}

// defaultAlphabetForRadix returns default alphabet string for a radix up to 36
func defaultAlphabetForRadix(radix int) string {
	base := "0123456789abcdefghijklmnopqrstuvwxyz"
	if radix <= 0 || radix > len(base) {
		return ""
	}
	return base[:radix]
}

// stringToIntsWithAlphabet converts string s to ints according to alphabet string
func stringToIntsWithAlphabet(s string, alphabet string) ([]int, error) {
	idx := make(map[byte]int, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		idx[alphabet[i]] = i
	}
	out := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		v, ok := idx[s[i]]
		if !ok {
			return nil, fmt.Errorf("char %c not in alphabet", s[i])
		}
		out[i] = v
	}
	return out, nil
}

// intsToStringWithAlphabet maps ints (0..radix-1) into string using alphabet.
func intsToStringWithAlphabet(a []int, alphabet string) (string, error) {
	sb := strings.Builder{}
	radix := len(alphabet)
	sb.Grow(len(a))
	for _, v := range a {
		if v < 0 || v >= radix {
			return "", fmt.Errorf("value %d out of range for radix %d", v, radix)
		}
		sb.WriteByte(alphabet[v])
	}
	return sb.String(), nil
}

// commonHMACBytesToHex produces an HMAC-like hex string for fallback deterministic mapping
func commonHMACBytesToHex(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
