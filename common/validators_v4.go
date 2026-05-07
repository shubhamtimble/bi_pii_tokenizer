package common

import (
	"errors"
	"regexp"
	"strings"
)

// PII types supported by v4.
const (
	PIITypePAN      = "PAN"
	PIITypeAADHAR   = "AADHAAR"
	PIITypeMobile   = "MOBILE"
	PIITypePhone    = "PHONE" // accepted alias for MOBILE (same validation + same FF1 path)
	PIITypeEmail    = "EMAIL"
	PIITypeDL       = "DL"
	PIITypePassport = "PASSPORT"
	PIITypeVoterID  = "VOTERID" // Indian EPIC: 3 letters + 7 digits
)

var (
	reV4PAN      = regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
	reV4Aadhar   = regexp.MustCompile(`^[0-9]{12}$`)
	reV4Mobile10 = regexp.MustCompile(`^[6-9][0-9]{9}$`)
	reV4Email    = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	reV4DL       = regexp.MustCompile(`^[A-Z0-9]{5,20}$`)
	reV4Passport = regexp.MustCompile(`^[A-Z][0-9]{7}$`)
	reV4VoterID  = regexp.MustCompile(`^[A-Z]{3}[0-9]{7}$`)

	reV4NonDigit = regexp.MustCompile(`[^0-9]`)
	reV4DLClean  = regexp.MustCompile(`[\s\-]`)
)

// ErrInvalidPII is returned for any format-rejection by NormalizeAndValidateV4.
var ErrInvalidPII = errors.New("invalid PII format")

// NormalizeAndValidateV4 canonicalizes a raw PII value for deduplication and
// rejects malformed inputs. It returns (normalized, nil) on success, or
// ("", error) with a user-facing message on failure.
func NormalizeAndValidateV4(piiType, value string) (string, error) {
	v := strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(piiType)) {
	case PIITypePAN:
		v = strings.ToUpper(v)
		if !reV4PAN.MatchString(v) {
			return "", errors.New("invalid PAN format")
		}
		return v, nil

	case PIITypeAADHAR:
		if !reV4Aadhar.MatchString(v) {
			return "", errors.New("invalid AADHAR format")
		}
		return v, nil

	case PIITypeMobile, PIITypePhone:
		v = strings.TrimPrefix(v, "+91")
		v = reV4NonDigit.ReplaceAllString(v, "")
		if !reV4Mobile10.MatchString(v) {
			return "", errors.New("invalid mobile format (expected 10 digits starting 6-9)")
		}
		return v, nil

	case PIITypeEmail:
		v = strings.ToLower(v)
		if !reV4Email.MatchString(v) {
			return "", errors.New("invalid email format")
		}
		return v, nil

	case PIITypeDL:
		v = strings.ToUpper(v)
		v = reV4DLClean.ReplaceAllString(v, "")
		if !reV4DL.MatchString(v) {
			return "", errors.New("invalid driving license format")
		}
		return v, nil

	case PIITypePassport:
		v = strings.ToUpper(v)
		if !reV4Passport.MatchString(v) {
			return "", errors.New("invalid passport format (expected 1 letter + 7 digits)")
		}
		return v, nil

	case PIITypeVoterID:
		v = strings.ToUpper(v)
		if !reV4VoterID.MatchString(v) {
			return "", errors.New("invalid voter id format (expected 3 letters + 7 digits)")
		}
		return v, nil

	default:
		return "", errors.New("unsupported pii_type")
	}
}
