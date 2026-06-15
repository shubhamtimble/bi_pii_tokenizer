package bi_internal

import "testing"

func TestMaskPII(t *testing.T) {
	cases := []struct {
		piiType string
		in      string
		maskCh  string
		want    string
	}{
		{"PAN", "ABCDE1234F", "X", "XXXXX1234F"},
		{"PAN", "ABCDE1234F", "*", "*****1234F"},
		{"PAN", "ABCDE1234F", "", "XXXXX1234F"}, // empty defaults to X
		{"AADHAAR", "123456789012", "X", "XXXXXXXX9012"},
		{"AADHAAR", "123456789012", "*", "********9012"},
		{"MOBILE", "9876543210", "X", "XXXXXX3210"},
		{"PHONE", "9876543210", "*", "******3210"},
		{"EMAIL", "test@gmail.com", "X", "XXXX@gmail.com"},
		{"EMAIL", "test@gmail.com", "*", "****@gmail.com"},
		{"PASSPORT", "A1234567", "X", "XXXXX567"},
		{"DL", "MH1420200001234", "*", "***********1234"},
		{"VOTERID", "ABC1234567", "X", "XXXXXXX567"},
		{"UNKNOWN", "whatever", "X", "XXXX"},
		{"UNKNOWN", "whatever", "*", "****"},
		{"pan", "ABCDE1234F", "X", "XXXXX1234F"}, // case-insensitive type
	}
	for _, c := range cases {
		if got := MaskPII(c.piiType, c.in, c.maskCh); got != c.want {
			t.Errorf("MaskPII(%q, %q, %q) = %q, want %q", c.piiType, c.in, c.maskCh, got, c.want)
		}
	}
}
