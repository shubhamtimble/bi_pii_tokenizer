package common

import (
	"testing"
	"time"
)

func TestDOBOrdinalRoundTrip(t *testing.T) {
	for _, d := range []string{"1900-01-01", "1975-09-30", "1998-01-05", "2000-02-29", "2000-12-20", "2099-12-31"} {
		parsed, err := time.Parse(dobLayout, d)
		if err != nil {
			t.Fatalf("parse %q: %v", d, err)
		}
		ord := dobToOrdinal(parsed)
		if ord < 0 || ord >= dobDomainSize() {
			t.Fatalf("ordinal %d for %q out of [0,%d)", ord, d, dobDomainSize())
		}
		if got := ordinalToDOB(ord); got != d {
			t.Fatalf("round trip %q -> %d -> %q", d, ord, got)
		}
	}
}

func TestDOBDomainSize(t *testing.T) {
	// 1900-01-01 .. 2099-12-31 inclusive = 73049 days
	if got := dobDomainSize(); got != 73049 {
		t.Fatalf("dobDomainSize = %d, want 73049", got)
	}
	// the fixed-width decimal encoding must cover the whole domain
	capacity := 1
	for i := 0; i < dobWidth; i++ {
		capacity *= 10
	}
	if dobDomainSize() > capacity {
		t.Fatalf("domain %d exceeds 10^%d encoding capacity", dobDomainSize(), dobWidth)
	}
}

func TestDOBEncodeDecodeInRange(t *testing.T) {
	if s, ok := dobDecodeInRange(dobEncodeOrdinal(0)); !ok || s != "1900-01-01" {
		t.Fatalf("decode ord 0 = %q ok=%v, want 1900-01-01", s, ok)
	}
	last := dobDomainSize() - 1
	if s, ok := dobDecodeInRange(dobEncodeOrdinal(last)); !ok || s != "2099-12-31" {
		t.Fatalf("decode last ord = %q ok=%v, want 2099-12-31", s, ok)
	}
	// an out-of-range 5-digit value must be rejected so the tokenizer cycle-walks
	if _, ok := dobDecodeInRange("99999"); ok {
		t.Fatalf("expected 99999 to be out of range")
	}
}

func TestValidateDOB(t *testing.T) {
	valid := []string{"2000-12-20", "1998-01-05", "1975-09-30", "1900-01-01", "2099-12-31", "2000-02-29"}
	for _, v := range valid {
		if got, err := ValidateDOB(v); err != nil || got != v {
			t.Errorf("ValidateDOB(%q) = (%q, %v), want (%q, nil)", v, got, err, v)
		}
	}
	invalid := []string{"20-12-2000", "2000/12/20", "2000-13-20", "2000-02-31", "2001-02-29", "2000-2-3", "abc", "", "1899-12-31", "2100-01-01"}
	for _, v := range invalid {
		if _, err := ValidateDOB(v); err == nil {
			t.Errorf("ValidateDOB(%q): expected error, got nil", v)
		}
	}
}
