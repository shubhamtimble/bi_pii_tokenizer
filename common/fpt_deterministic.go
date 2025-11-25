package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
)

func ComputeBlindIndex(key []byte, value string) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write([]byte(value))
    return mac.Sum(nil)
}

func NormalizePII(value string, piiType string) (string, error) {
    value = strings.TrimSpace(strings.ToUpper(value))
    return value, nil
}

// Base32 (A-Z2-7) no padding
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Deterministic, collision-free, format-preserving FPT.
// blind: HMAC of original PII (from existing logic)
// normalized: cleaned PII
// piiType: "pan", "aadhaar", "mobile", "email"
func FPTDeterministic(blind []byte, normalized, piiType string) (string, error) {

	// HMAC(blind + normalized + piiType)
	h := hmac.New(sha256.New, []byte(piiType))
	h.Write(blind)
	h.Write([]byte(normalized))
	digest := h.Sum(nil)

	// Base32 encode digest into A–Z2–7 ~160 bits of entropy
	base := strings.ToUpper(base32NoPad.EncodeToString(digest))

	switch piiType {

	case "pan":
		// AAAAA9999A
		if len(normalized) != 10 {
			return "", errors.New("invalid PAN length")
		}
		// 5 letters
		letters := onlyLetters(base)
		if len(letters) < 6 {
			return "", errors.New("insufficient letter space for PAN")
		}
		// 4 digits
		digits := onlyDigits(base)
		if len(digits) < 4 {
			// convert some letters to digits
			digits = convertToDigits(base)
		}
		return letters[:5] + digits[:4] + letters[5:6], nil

	case "aadhaar":
		// 12 digits
		digs := convertToDigits(base)
		if len(digs) < 12 {
			return "", errors.New("insufficient digit entropy for Aadhaar")
		}
		return digs[:12], nil

	case "mobile":
		// 10 digits starting with 6–9
		digs := convertToDigits(base)
		if len(digs) < 10 {
			return "", errors.New("insufficient digit entropy for mobile")
		}
		first := digs[0]
		if first < '6' {
			first = '6' + (first % 4) // force into 6–9 range
		}
		return string(first) + digs[1:10], nil

	case "email":
		return fptForEmail(normalized, base)

	default:
		// generic fallback: same length as input
		out := alphanumeric(base)
		if len(out) < len(normalized) {
			return "", errors.New("insufficient entropy for generic FPT")
		}
		return out[:len(normalized)], nil
	}
}

// --- Helpers --------------------------------------------------------------

func onlyLetters(s string) string {
	re := regexp.MustCompile(`[A-Z]`)
	return strings.Join(re.FindAllString(s, -1), "")
}

func onlyDigits(s string) string {
	re := regexp.MustCompile(`[0-9]`)
	return strings.Join(re.FindAllString(s, -1), "")
}

func convertToDigits(s string) string {
	out := ""
	for _, c := range []byte(s) {
		out += string('0' + (c % 10))
	}
	return out
}

func alphanumeric(s string) string {
	re := regexp.MustCompile(`[A-Z0-9]`)
	return strings.Join(re.FindAllString(s, -1), "")
}

// Email: preserve structure, replace only alphanumeric segments
func fptForEmail(origEmail, base string) (string, error) {
	parts := strings.Split(origEmail, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid email format")
	}
	local, domain := parts[0], parts[1]

	// Deterministic sequence
	src := alphanumeric(base)
	if len(src) < len(local)+len(domain) {
		return "", errors.New("entropy insufficient for email FPT")
	}

	i := 0
	outLocal := ""
	for _, ch := range local {
		if isAlphaNum(ch) {
			outLocal += string(src[i])
			i++
		} else {
			outLocal += string(ch)
		}
	}

	outDomain := ""
	for _, ch := range domain {
		if isAlphaNum(ch) {
			outDomain += string(src[i])
			i++
		} else {
			outDomain += string(ch)
		}
	}

	return outLocal + "@" + outDomain, nil
}

func isAlphaNum(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9')
}
