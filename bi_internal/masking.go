package bi_internal

import "strings"

// MaskPII masks a decrypted PII value with the given fill character (maskChar),
// keeping a small trailing identifying portion so the value is recognizable but
// not disclosed. maskChar is "X" or "*"; an empty value defaults to "X". Only
// invoked for MASKED detokenize access. piiType uses the canonical codes stored
// in pii_tokens.data_type (PAN, AADHAAR, MOBILE, PHONE, EMAIL, DL, PASSPORT,
// VOTERID, DATE_OF_BIRTH).
//
//	PAN           ABCDE1234F      -> XXXXX1234F  (or *****1234F)
//	AADHAAR       123456789012    -> XXXXXXXX9012
//	MOBILE        9876543210      -> XXXXXX3210
//	EMAIL         test@gmail.com  -> XXXX@gmail.com
//	PASSPORT      A1234567        -> XXXXX567
//	DL            MH1420200001234 -> XXXXXXXXXXX2345
//	VOTERID       ABC1234567      -> XXXXXXX567
//	DATE_OF_BIRTH 2000-12-20      -> XXXX-XX-XX  (all digits hidden, hyphens kept)
func MaskPII(piiType, value, maskChar string) string {
	ch := maskChar
	if ch == "" {
		ch = "X"
	}
	switch strings.ToUpper(strings.TrimSpace(piiType)) {
	case "PAN":
		return maskKeepLast(value, 5, ch)
	case "AADHAAR":
		return maskKeepLast(value, 4, ch)
	case "MOBILE", "PHONE":
		return maskKeepLast(value, 4, ch)
	case "PASSPORT":
		return maskKeepLast(value, 3, ch)
	case "DL":
		return maskKeepLast(value, 4, ch)
	case "VOTERID":
		return maskKeepLast(value, 3, ch)
	case "EMAIL":
		return maskEmail(value, ch)
	case "DATE_OF_BIRTH":
		return maskDOB(value, ch)
	default:
		return strings.Repeat(ch, 4)
	}
}

// maskDOB hides every digit of a YYYY-MM-DD date with `ch` while preserving the
// hyphens, e.g. 2000-12-20 -> XXXX-XX-XX. The real year is intentionally hidden
// so a masked DOB cannot be used to infer age.
func maskDOB(v, ch string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteString(ch)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// maskKeepLast replaces all but the last `keep` characters with `ch`. If the
// value is shorter than `keep`, the whole value is masked.
func maskKeepLast(v string, keep int, ch string) string {
	if len(v) <= keep {
		return strings.Repeat(ch, len(v))
	}
	return strings.Repeat(ch, len(v)-keep) + v[len(v)-keep:]
}

// maskEmail masks the local part with `ch` and preserves "@domain" verbatim.
func maskEmail(v, ch string) string {
	at := strings.LastIndexByte(v, '@')
	if at <= 0 {
		return strings.Repeat(ch, 4)
	}
	return strings.Repeat(ch, at) + v[at:]
}
