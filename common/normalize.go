package common

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// reNonDigit matches anything that isn't a digit; used by mobile/phone
// normalization to strip spaces, dashes, parens, etc.
var reNonDigit = regexp.MustCompile(`[^0-9]`)

// Normalize returns the canonical form of a PII value for a given type. This is
// the form used by both the legacy tokenize blind index and the v2 audit log
// value_hash so that the same logical PII always produces the same hash.
func Normalize(piiType, value string) string {
	switch strings.ToUpper(strings.TrimSpace(piiType)) {
	case "PAN", "PASSPORT", "VOTERID":
		return strings.ToUpper(strings.TrimSpace(value))
	case "EMAIL":
		return strings.ToLower(strings.TrimSpace(value))
	case "PHONE", "MOBILE":
		v := strings.TrimSpace(value)
		v = strings.TrimPrefix(v, "+91")
		return reNonDigit.ReplaceAllString(v, "")
	case "DL":
		v := strings.ToUpper(strings.TrimSpace(value))
		return regexp.MustCompile(`[\s\-]`).ReplaceAllString(v, "")
	case "DATE_OF_BIRTH":
		// already canonical YYYY-MM-DD; just trim
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(value)
	}
}

// ValueHash returns "sha256:<hex>" for forensic correlation in audit logs.
// Hash the *normalized* value so equivalent inputs produce the same hash.
// The plaintext itself is NEVER stored anywhere — this hash is one-way.
func ValueHash(normalized string) string {
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(sum[:])
}
