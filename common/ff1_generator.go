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
		alphabet:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+",
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

// Map custom valid email characters to indices in alphabet and back.
// Alphabet: 0-9 (10), a-z (26), A-Z (26), .,-,_,+ (4) = 66 chars
// We use a custom radix 40 for Email: 0-9, a-z, ., -, _, +
//  0-9 -> 0-9
//  a-z -> 10-35
//  .   -> 36
//  -   -> 37
//  _   -> 38
//  +   -> 39
// Note: Uppercase letters will be normalized to lowercase before tokenization.
func (g *FF1Generator) encodeEmailCharsToValues(s string) ([]int, error) {
	out := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'z':
			v = int(c - 'a') + 10
		case c == '.':
			v = 36
		case c == '-':
			v = 37
		case c == '_':
			v = 38
		case c == '+':
			v = 39
		default:
			return nil, fmt.Errorf("invalid email char for FPT: %c", c)
		}
		out[i] = v
	}
	return out, nil
}

func (g *FF1Generator) decodeValuesToEmailChars(vals []int) (string, error) {
	var sb strings.Builder
	for _, v := range vals {
		var c byte
		switch {
		case v >= 0 && v <= 9:
			c = byte('0' + v)
		case v >= 10 && v <= 35:
			c = byte('a' + (v - 10))
		case v == 36:
			c = '.'
		case v == 37:
			c = '-'
		case v == 38:
			c = '_'
		case v == 39:
			c = '+'
		default:
			return "", fmt.Errorf("decoded value out of range for email: %d", v)
		}
		sb.WriteByte(c)
	}
	return sb.String(), nil
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

	case "PHONE":
		// Expect 10 digits
		if len(normalized) != 10 {
			return "", fmt.Errorf("PHONE must be 10 digits")
		}
		// Validate digits
		_, err := mustDigits(normalized, 10)
		if err != nil {
			return "", err
		}
		// Treat as single block radix 10
		// 1. values
		vals := make([]int, 10)
		for i := 0; i < 10; i++ {
			vals[i] = int(normalized[i] - '0')
		}
		// 2. encode
		plainStr, err := g.encodeValuesToAlphabet(vals, 10)
		if err != nil {
			return "", fmt.Errorf("encode phone: %w", err)
		}
		// 3. encrypt
		ctStr, err := g.encryptStringWithTweak(10, plainStr, tweak)
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt phone: %w", err)
		}
		// 4. decode
		outVals, err := g.decodeAlphabetToValues(ctStr, 10)
		if err != nil {
			return "", fmt.Errorf("decode phone cipher output: %w", err)
		}
		// 5. stringify
		out := make([]byte, 10)
		for i, v := range outVals {
			out[i] = byte('0' + v)
		}
		return string(out), nil

	case "EMAIL":
		// Strategy: LocalPart @ Domain
		// Split
		parts := strings.Split(normalized, "@")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid email format")
		}
		local := parts[0]
		domain := parts[1]
		if local == "" || domain == "" {
			return "", fmt.Errorf("empty email parts")
		}

		// Encrypt Local Part (Radix 40)
		localVals, err := g.encodeEmailCharsToValues(local)
		if err != nil {
			return "", err
		}
		localPlain, err := g.encodeValuesToAlphabet(localVals, 40)
		if err != nil {
			return "", err
		}
		localCipher, err := g.encryptStringWithTweak(40, localPlain, tweak)
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt email local: %w", err)
		}
		localOutVals, err := g.decodeAlphabetToValues(localCipher, 40)
		if err != nil {
			return "", err
		}
		localOut, err := g.decodeValuesToEmailChars(localOutVals)
		if err != nil {
			return "", err
		}

		// Encrypt Domain Part (Radix 40)
		domainVals, err := g.encodeEmailCharsToValues(domain)
		if err != nil {
			return "", err
		}
		domainPlain, err := g.encodeValuesToAlphabet(domainVals, 40)
		if err != nil {
			return "", err
		}
		domainCipher, err := g.encryptStringWithTweak(40, domainPlain, tweak) // Re-use tweak? Ideally should differentiate but Tweak logic is simpler here
		if err != nil {
			return "", fmt.Errorf("ff1 encrypt email domain: %w", err)
		}
		domainOutVals, err := g.decodeAlphabetToValues(domainCipher, 40)
		if err != nil {
			return "", err
		}
		domainOut, err := g.decodeValuesToEmailChars(domainOutVals)
		if err != nil {
			return "", err
		}

		return localOut + "@" + domainOut, nil

	default:
		// fallback deterministic mapping (non-crypto)
		return deterministicBase36FromHexWithCounter(hex.EncodeToString(g.key), len(normalized), 0)
	}
}
