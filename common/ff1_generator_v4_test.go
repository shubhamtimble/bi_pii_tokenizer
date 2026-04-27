package common

import (
	"crypto/rand"
	"regexp"
	"testing"
)

func newTestGen(t *testing.T) *FF1GeneratorV4 {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	g, err := NewFF1GeneratorV4(key, "test")
	if err != nil {
		t.Fatalf("NewFF1GeneratorV4: %v", err)
	}
	return g
}

func mustTweak(t *testing.T) []byte {
	t.Helper()
	tw, err := RandomTweak()
	if err != nil {
		t.Fatalf("RandomTweak: %v", err)
	}
	return tw
}

func TestFF1_PAN_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	panRE := regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)

	ct, err := g.TokenizePAN("ABCDE1234F", tw)
	if err != nil {
		t.Fatalf("TokenizePAN: %v", err)
	}
	if !panRE.MatchString(ct) {
		t.Fatalf("PAN ciphertext %q violates format 5L4D1L", ct)
	}

	// same input + same tweak -> deterministic
	ct2, _ := g.TokenizePAN("ABCDE1234F", tw)
	if ct != ct2 {
		t.Fatalf("PAN not deterministic: %q vs %q", ct, ct2)
	}
}

func TestFF1_PAN_DifferentTweakDifferentOutput(t *testing.T) {
	g := newTestGen(t)
	tw1 := mustTweak(t)
	tw2 := mustTweak(t)
	ct1, _ := g.TokenizePAN("ABCDE1234F", tw1)
	ct2, _ := g.TokenizePAN("ABCDE1234F", tw2)
	if ct1 == ct2 {
		t.Fatalf("expected different tweaks to produce different FPTs, both=%q", ct1)
	}
}

func TestFF1_AADHAR_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	ct, err := g.TokenizeAADHAR("123456789012", tw)
	if err != nil {
		t.Fatalf("TokenizeAADHAR: %v", err)
	}
	if len(ct) != 12 {
		t.Fatalf("expected 12 digits, got %q", ct)
	}
	for _, c := range ct {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit %c in AADHAR ciphertext %q", c, ct)
		}
	}
}

func TestFF1_Mobile_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	ct, err := g.TokenizeMobile("9876543210", tw)
	if err != nil {
		t.Fatalf("TokenizeMobile: %v", err)
	}
	if len(ct) != 10 {
		t.Fatalf("expected 10 digits, got %q", ct)
	}
	for _, c := range ct {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit %c in mobile ciphertext %q", c, ct)
		}
	}
}

func TestFF1_Passport_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	ct, err := g.TokenizePassport("A1234567", tw)
	if err != nil {
		t.Fatalf("TokenizePassport: %v", err)
	}
	if len(ct) != 8 {
		t.Fatalf("expected 8 chars, got %q", ct)
	}
	if ct[0] < 'A' || ct[0] > 'Z' {
		t.Fatalf("first char not A-Z: %q", ct)
	}
	for i := 1; i < 8; i++ {
		if ct[i] < '0' || ct[i] > '9' {
			t.Fatalf("pos %d not digit: %q", i, ct)
		}
	}
}

func TestFF1_Email_PreservesStructure(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	ct, err := g.TokenizeEmail("user.name+tag@sub.example.co.in", tw)
	if err != nil {
		t.Fatalf("TokenizeEmail: %v", err)
	}
	// must contain exactly one '@' and the same '.' structure in domain
	atCount := 0
	for _, c := range ct {
		if c == '@' {
			atCount++
		}
	}
	if atCount != 1 {
		t.Fatalf("expected 1 @, got %d in %q", atCount, ct)
	}
	// domain should still have three dots (sub.example.co.in -> 3 dots)
	domain := ct[len(ct)-len("sub.example.co.in"):]
	_ = domain
	dotCount := 0
	afterAt := false
	for _, c := range ct {
		if c == '@' {
			afterAt = true
			continue
		}
		if afterAt && c == '.' {
			dotCount++
		}
	}
	if dotCount != 3 {
		t.Fatalf("expected 3 dots in domain, got %d in %q", dotCount, ct)
	}
}

func TestFF1_DL_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	ct, err := g.TokenizeDL("MH1420200001234", tw)
	if err != nil {
		t.Fatalf("TokenizeDL: %v", err)
	}
	if len(ct) != len("MH1420200001234") {
		t.Fatalf("DL length changed: in=%d out=%d", len("MH1420200001234"), len(ct))
	}
	for _, c := range ct {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
			t.Fatalf("DL contains non-alphanumeric char %c in %q", c, ct)
		}
	}
}

func TestFF1_VoterID_FormatPreserved(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	voterRE := regexp.MustCompile(`^[A-Z]{3}[0-9]{7}$`)

	ct, err := g.TokenizeVoterID("ABC1234567", tw)
	if err != nil {
		t.Fatalf("TokenizeVoterID: %v", err)
	}
	if !voterRE.MatchString(ct) {
		t.Fatalf("VOTERID ciphertext %q violates 3L7D format", ct)
	}
	// deterministic for same input + tweak
	ct2, _ := g.TokenizeVoterID("ABC1234567", tw)
	if ct != ct2 {
		t.Fatalf("VOTERID not deterministic: %q vs %q", ct, ct2)
	}
}

func TestFF1_DifferentInputs_DifferentOutputs(t *testing.T) {
	g := newTestGen(t)
	tw := mustTweak(t)
	a, _ := g.TokenizeAADHAR("111122223333", tw)
	b, _ := g.TokenizeAADHAR("999988887777", tw)
	if a == b {
		t.Fatalf("different AADHARs produced same FPT: %q", a)
	}
}
