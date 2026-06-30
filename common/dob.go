package common

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DATE_OF_BIRTH (DOB) format-preserving tokenization helpers.
//
// A DOB is stored/transmitted strictly as YYYY-MM-DD and tokenizes to ANOTHER
// valid calendar date in the same format. To guarantee the token is always a
// real date, the value is encoded as an ordinal day-count within a fixed range
// [dobEpoch, dobMaxExclusive); the tokenizers map that ordinal to a new ordinal
// in the same range and decode it back via calendar arithmetic. The token's
// year may differ from the real one — by design, so the token cannot be used to
// infer age/eligibility. The real DOB is recovered through the normal
// detokenize flow (storage-backed AES decrypt), never by inverting this map.
const dobLayout = "2006-01-02"

// dobWidth is the decimal width used to render the ordinal for radix-10 FF1.
// 10^5 = 100000 >= dobDomainSize (73049), so 5 digits cover the whole range.
const dobWidth = 5

var (
	// Supported DOB window: 1900-01-01 .. 2099-12-31 inclusive.
	dobEpoch       = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	dobMaxExclusive = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	// dobDomainSizeVal = number of days in [dobEpoch, dobMaxExclusive). Computed
	// once; the difference is an exact multiple of 24h (both bounds at UTC
	// midnight), so integer-hour division is exact.
	dobDomainSizeVal = int(dobMaxExclusive.Sub(dobEpoch).Hours()) / 24

	reDOB = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// dobDomainSize returns the number of distinct dates in the supported range.
func dobDomainSize() int { return dobDomainSizeVal }

// ValidateDOB enforces the strict YYYY-MM-DD contract and returns the canonical
// (trimmed) value. It rejects wrong shapes (20-12-2000, 2000/12/20), non-real
// calendar dates (2000-13-20, 2000-02-31), and dates outside the supported
// range. Used by both the v4 and legacy validation paths.
func ValidateDOB(value string) (string, error) {
	v := strings.TrimSpace(value)
	if !reDOB.MatchString(v) {
		return "", errors.New("invalid DOB format (expected YYYY-MM-DD)")
	}
	t, err := time.Parse(dobLayout, v)
	if err != nil {
		return "", errors.New("invalid DOB (not a real calendar date)")
	}
	// Round-trip guard: time.Parse rejects out-of-range month/day, but this also
	// catches any normalization drift so the stored value is exactly canonical.
	if t.Format(dobLayout) != v {
		return "", errors.New("invalid DOB (not a real calendar date)")
	}
	if t.Before(dobEpoch) || !t.Before(dobMaxExclusive) {
		return "", errors.New("DOB out of supported range (1900-01-01..2099-12-31)")
	}
	return v, nil
}

// dobToOrdinal returns the day offset of t from dobEpoch (t assumed already
// validated to be in range). Result is in [0, dobDomainSize).
func dobToOrdinal(t time.Time) int {
	return int(t.UTC().Sub(dobEpoch).Hours()) / 24
}

// ordinalToDOB decodes a day offset back to a YYYY-MM-DD string via calendar
// arithmetic, so the result is always a valid date in range.
func ordinalToDOB(ord int) string {
	return dobEpoch.AddDate(0, 0, ord).Format(dobLayout)
}

// dobEncodeOrdinal renders an ordinal as a fixed-width decimal string for FF1.
func dobEncodeOrdinal(ord int) string {
	s := strconv.Itoa(ord)
	for len(s) < dobWidth {
		s = "0" + s
	}
	return s
}

// dobDecodeInRange parses a dobWidth-digit string and, if it falls inside the
// supported domain, returns the decoded YYYY-MM-DD and true. Out-of-range values
// return false so the caller can cycle-walk (re-encrypt) to stay in range.
func dobDecodeInRange(digits string) (string, bool) {
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 || n >= dobDomainSize() {
		return "", false
	}
	return ordinalToDOB(n), true
}
