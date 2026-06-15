package common

import "testing"

func TestNormalizeAndValidateV4_PAN(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"ABCDE1234F", "ABCDE1234F", true},
		{"abcde1234f", "ABCDE1234F", true},
		{"  ABCDE1234F ", "ABCDE1234F", true},
		{"ABCDE12345", "", false},
		{"ABCDE1234", "", false},
		{"ABCDE1234FG", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypePAN, c.in)
		if (err == nil) != c.ok {
			t.Errorf("PAN %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("PAN %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_AADHAR(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"123456789012", "123456789012", true},
		{"12345678901", "", false},
		{"1234567890123", "", false},
		{"12345678901A", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypeAADHAR, c.in)
		if (err == nil) != c.ok {
			t.Errorf("AADHAR %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("AADHAR %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_Mobile(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"9876543210", "9876543210", true},
		{"+919876543210", "9876543210", true},
		{"+91 98765 43210", "9876543210", true},
		{"98-76-543210", "9876543210", true},
		{"5876543210", "", false}, // must start 6-9
		{"987654321", "", false},  // 9 digits
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypeMobile, c.in)
		if (err == nil) != c.ok {
			t.Errorf("MOBILE %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("MOBILE %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_Email(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"user@example.com", "user@example.com", true},
		{"USER@Example.COM", "user@example.com", true},
		{"first.last+tag@sub.example.co.in", "first.last+tag@sub.example.co.in", true},
		{"no-at-sign", "", false},
		{"@nohost.com", "", false},
		{"noatsign@", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypeEmail, c.in)
		if (err == nil) != c.ok {
			t.Errorf("EMAIL %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("EMAIL %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_DL(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"MH1420200001234", "MH1420200001234", true},
		{"MH-14-20200001234", "MH1420200001234", true},
		{"mh 14 20200001234", "MH1420200001234", true},
		{"AB12", "", false},               // too short
		{"ABCDE1234F", "", false},         // PAN-shaped — strict DL must reject
		{"MH142020000123", "", false},     // 14 chars (12 digits) — too short
		{"MH14202000012345", "", false},   // 16 chars (14 digits) — too long
		{"M123456789012345", "", false},   // 1 letter prefix — needs 2
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypeDL, c.in)
		if (err == nil) != c.ok {
			t.Errorf("DL %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("DL %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_Passport(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"A1234567", "A1234567", true},
		{"a1234567", "A1234567", true},
		{"A123456", "", false},
		{"12345678", "", false},
		{"AB234567", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypePassport, c.in)
		if (err == nil) != c.ok {
			t.Errorf("PASSPORT %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("PASSPORT %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_VoterID(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"ABC1234567", "ABC1234567", true},
		{"abc1234567", "ABC1234567", true},
		{"  XYZ9876543 ", "XYZ9876543", true},
		{"AB12345678", "", false},     // 2 letters
		{"ABCD123456", "", false},     // 4 letters
		{"ABC123456", "", false},      // 9 chars
		{"ABC12345678", "", false},    // 11 chars
		{"123ABC4567", "", false},     // letters not in front
		{"", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeAndValidateV4(PIITypeVoterID, c.in)
		if (err == nil) != c.ok {
			t.Errorf("VOTERID %q: ok=%v want=%v err=%v", c.in, err == nil, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Errorf("VOTERID %q: got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestNormalizeAndValidateV4_UnknownType(t *testing.T) {
	if _, err := NormalizeAndValidateV4("DNA", "whatever"); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}
