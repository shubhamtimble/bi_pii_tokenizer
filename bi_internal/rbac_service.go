package bi_internal

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// errInvalidValidityPeriod is returned by validityUntil for an unrecognized
// validity_period value.
var errInvalidValidityPeriod = errors.New("invalid validity_period")

// reValidityDays matches a custom "<N>_DAYS" validity period (also matches the
// former fixed values like 15_DAYS, 30_DAYS, etc.).
var reValidityDays = regexp.MustCompile(`^(\d+)_DAYS$`)

// normalizePermPIIType maps the data_type used in the vault to the canonical
// permission key. PHONE and MOBILE share validation and the same FF1 path, so a
// MOBILE permission row also governs tokens stored as PHONE.
func normalizePermPIIType(piiType string) string {
	t := strings.ToUpper(strings.TrimSpace(piiType))
	if t == "PHONE" {
		return "MOBILE"
	}
	return t
}

// CanTokenize reports whether a role may tokenize a given PII type.
// Returns (allowed, expired, err): expired is true when a matching permission
// exists but its validity window has passed (so the caller can return the
// "permission expired" message); err is non-nil only on a DB-fallback failure.
func (r *RBAC) CanTokenize(ctx context.Context, roleCode, piiType string) (bool, bool, error) {
	p, found, err := r.getPIIPerm(ctx, roleCode, normalizePermPIIType(piiType))
	if err != nil {
		return false, false, err
	}
	if !found || !p.active() {
		return false, false, nil
	}
	if p.expired(time.Now().UTC()) {
		return false, true, nil
	}
	return p.CanTokenize, false, nil
}

// GetDetokenizeAccess returns the detokenize access level + mask character for a
// (role, PII type). Returns (access, maskChar, expired, found, err). access is
// AccessNone when not found, inactive, or expired; maskChar defaults to "X".
func (r *RBAC) GetDetokenizeAccess(ctx context.Context, roleCode, piiType string) (DetokenizeAccess, string, bool, bool, error) {
	p, found, err := r.getPIIPerm(ctx, roleCode, normalizePermPIIType(piiType))
	if err != nil {
		return AccessNone, "X", false, false, err
	}
	if !found || !p.active() {
		return AccessNone, "X", false, false, nil
	}
	mask := p.MaskChar
	if mask == "" {
		mask = "X"
	}
	if p.expired(time.Now().UTC()) {
		return AccessNone, mask, true, true, nil
	}
	return p.DetokenizeAccess, mask, false, true, nil
}

// validityUntil computes valid_until from a validity_period and a start time.
// Accepts "FOREVER" (no expiry), any "<N>_DAYS" (custom days, N >= 1), and the
// legacy "1_YEAR". Returns an error for anything else.
func validityUntil(period string, from time.Time) (*time.Time, error) {
	p := strings.ToUpper(strings.TrimSpace(period))
	if p == "FOREVER" {
		return nil, nil
	}
	if p == "1_YEAR" { // legacy fixed value
		t := from.AddDate(1, 0, 0)
		return &t, nil
	}
	if m := reValidityDays.FindStringSubmatch(p); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 {
			return nil, errInvalidValidityPeriod
		}
		t := from.AddDate(0, 0, n)
		return &t, nil
	}
	return nil, errInvalidValidityPeriod
}
