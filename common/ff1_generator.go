package common

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	ff1lib "github.com/capitalone/fpe/ff1"
)

/*
FF1Generator (string-API)
- Uses ff1.Cipher.EncryptWithTweak(plaintext string, tweak []byte) (string, error)
- Builds plaintext strings by encoding values into the canonical FF1 alphabet:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
  and using its first `radix` characters as the cipher alphabet.
- For PAN:
    * letters (5 chars) -> values 0..25 -> encode using alphabet[:26] -> encrypt -> decode -> map 0..25 -> 'A'..'Z'
    * digits (4 chars)  -> values 0..9  -> encode using alphabet[:10] -> encrypt -> decode -> '0'..'9'
    * last letter (1 char) same as letters
*/

type FF1Generator struct {
	key        []byte
	keyVersion string
	maxTLen    int
	// canonical alphabet for encoding numeric values as characters for string API
	alphabet string
}

func NewFF1Generator(key []byte, keyVersion string) (*FF1Generator, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("empty FPE key")
	}
	return &FF1Generator{
		key:        key,
		keyVersion: keyVersion,
		maxTLen:    64,
		alphabet:   "0123456789abcdefghijklmnopqrstuvwxyz",
	}, nil
}

func (g *FF1Generator) KeyVersion() string { return g.keyVersion }

// helper: ensure letters are uppercase A..Z and digits valid
func mustUpperLetters(s string, expected int) (string, error) {
	if len(s) != expected {
		return "", fmt.Errorf("invalid letters length: want %d got %d", expected, len(s))
	}
	out := make([]byte, expected)
	for i := 0; i < expected; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		if c < 'A' || c > 'Z' {
			return "", fmt.Errorf("invalid letter char: %c", c)
		}
		out[i] = c
	}
	return string(out), nil
}

func mustDigits(s string, expected int) (string, error) {
	if expected >= 0 && len(s) != expected {
		return "", fmt.Errorf("invalid digits length: want %d got %d", expected, len(s))
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return "", fmt.Errorf("invalid digit char: %c", c)
		}
		out[i] = c
	}
	return string(out), nil
}

// encodeValuesToAlphabet builds plaintext string for given values [0..radix-1]
// by using the first `radix` characters of g.alphabet.
func (g *FF1Generator) encodeValuesToAlphabet(values []int, radix int) (string, error) {
	if radix <= 0 || radix > len(g.alphabet) {
		return "", fmt.Errorf("invalid radix: %d", radix)
	}
	alpha := g.alphabet[:radix]
	out := make([]byte, len(values))
	for i, v := range values {
		if v < 0 || v >= radix {
			return "", fmt.Errorf("value out of range for radix %d: %d", radix, v)
		}
		out[i] = alpha[v]
	}
	return string(out), nil
}

// decodeAlphabetToValues maps each character of s (must be from alphabet[:radix])
// to its index value 0..radix-1
func (g *FF1Generator) decodeAlphabetToValues(s string, radix int) ([]int, error) {
	if radix <= 0 || radix > len(g.alphabet) {
		return nil, fmt.Errorf("invalid radix: %d", radix)
	}
	alpha := g.alphabet[:radix]
	values := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(alpha, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("cipher returned char not in radix alphabet: %c", s[i])
		}
		values[i] = idx
	}
	return values, nil
}

// helper to create cipher for radix and call EncryptWithTweak
func (g *FF1Generator) encryptStringWithTweak(radix int, plaintext string, tweak []byte) (string, error) {
	cipher, err := ff1lib.NewCipher(radix, g.maxTLen, g.key, nil)
	if err != nil {
		return "", fmt.Errorf("ff1 NewCipher(radix=%d) error: %w", radix, err)
	}
	// call EncryptWithTweak (your ff1 build exposes this method)
	ct, err := cipher.EncryptWithTweak(plaintext, tweak)
	if err != nil {
		return "", fmt.Errorf("ff1 EncryptWithTweak error: %w", err)
	}
	return ct, nil
}

// GenerateToken: segmented PAN + AADHAR handling
func (g *FF1Generator) GenerateToken(ctx context.Context, dataType, normalized string, tweak []byte) (string, error) {
	switch strings.ToUpper(dataType) {
		case "PAN":
		if len(normalized) != 10 {
			return "", fmt.Errorf("PAN must be 10 chars, got %d", len(normalized))
		}

		// Validate & uppercase
		lettersPrefix, err := mustUpperLetters(normalized[0:5], 5)
		if err != nil {
			return "", err
		}
		digits, err := mustDigits(normalized[5:9], 4)
		if err != nil {
			return "", err
		}
		lastLetter, err := mustUpperLetters(normalized[9:10], 1)
		if err != nil {
			return "", err
		}

		// --------- LETTERS: combine prefix (5) + last (1) -> 6-char block, radix 26 ----------
		// Map letters to values 0..25
		combinedLettersVals := make([]int, 6)
		for i := 0; i < 5; i++ {
			combinedLettersVals[i] = int(lettersPrefix[i] - 'A')
		}
		combinedLettersVals[5] = int(lastLetter[0] - 'A')

		// Encode values into alphabet[:26] and encrypt as a single block
		plainLettersStr, err := g.encodeValuesToAlphabet(combinedLettersVals, 26)
		if err != nil {
			return "", fmt.Errorf("encode combined letters: %w", err)
		}
		ctLettersStr, err := g.encryptStringWithTweak(26, plainLettersStr, tweak)
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt combined letters: %w", err)
		}
		// Decode ciphertext string back to numeric values
		ctLettersVals, err := g.decodeAlphabetToValues(ctLettersStr, 26)
		if err != nil {
			return "", fmt.Errorf("decode combined letters cipher output: %w", err)
		}
		if len(ctLettersVals) != 6 {
			return "", fmt.Errorf("unexpected combined letters output length: %d", len(ctLettersVals))
		}
		// Map back to letters: first 5 are prefix, 6th is last
		ctLettersPrefix := make([]byte, 5)
		for i := 0; i < 5; i++ {
			v := ctLettersVals[i]
			if v < 0 || v >= 26 {
				return "", fmt.Errorf("combined letters out of range: %d", v)
			}
			ctLettersPrefix[i] = byte('A' + v)
		}
		ctLast := ctLettersVals[5]
		if ctLast < 0 || ctLast >= 26 {
			return "", fmt.Errorf("combined last-letter out of range: %d", ctLast)
		}
		ctLastByte := byte('A' + ctLast)

		// --------- DIGITS: 4-char block (radix 10) ----------
		digVals := make([]int, 4)
		for i := 0; i < 4; i++ {
			digVals[i] = int(digits[i] - '0')
		}
		plainDigitsStr, err := g.encodeValuesToAlphabet(digVals, 10)
		if err != nil {
			return "", fmt.Errorf("encode digits: %w", err)
		}
		ctDigitsStr, err := g.encryptStringWithTweak(10, plainDigitsStr, tweak)
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt digits: %w", err)
		}
		ctDigitVals, err := g.decodeAlphabetToValues(ctDigitsStr, 10)
		if err != nil {
			return "", fmt.Errorf("decode digits cipher output: %w", err)
		}
		if len(ctDigitVals) != 4 {
			return "", fmt.Errorf("unexpected digits output length: %d", len(ctDigitVals))
		}
		ctDigits := make([]byte, 4)
		for i, v := range ctDigitVals {
			if v < 0 || v >= 10 {
				return "", fmt.Errorf("digits cipher out of range: %d", v)
			}
			ctDigits[i] = byte('0' + v)
		}

		// Assemble final PAN: prefix(5) + digits(4) + last(1)
		return strings.ToUpper(string(ctLettersPrefix) + string(ctDigits) + string(ctLastByte)), nil


	case "AADHAR":
		// digits-only arbitrary length
		plain, err := mustDigits(normalized, -1)
		if err != nil {
			return "", err
		}
		// convert to values
		vals := make([]int, len(plain))
		for i := 0; i < len(plain); i++ {
			vals[i] = int(plain[i] - '0')
		}
		plainStr, err := g.encodeValuesToAlphabet(vals, 10)
		if err != nil {
			return "", fmt.Errorf("encode aadhar: %w", err)
		}
		ctStr, err := g.encryptStringWithTweak(10, plainStr, tweak)
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt aadhar: %w", err)
		}
		outVals, err := g.decodeAlphabetToValues(ctStr, 10)
		if err != nil {
			return "", fmt.Errorf("decode aadhar cipher output: %w", err)
		}
		out := make([]byte, len(outVals))
		for i, v := range outVals {
			if v < 0 || v >= 10 {
				return "", fmt.Errorf("aadhar cipher out of range: %d", v)
			}
			out[i] = byte('0' + v)
		}
		return string(out), nil

	default:
		// fallback deterministic mapping (non-crypto)
		return deterministicBase36FromHexWithCounter(hex.EncodeToString(g.key), len(normalized), 0)
	}
}
