package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	ff1lib "github.com/capitalone/fpe/ff1"
)

// FF1GeneratorV4 generates FF1-based format-preserving tokens for v4.
// It caches cipher objects per radix to avoid repeated key scheduling.
type FF1GeneratorV4 struct {
	key        []byte
	keyVersion string
	maxTLen    int

	mu      sync.RWMutex
	ciphers map[int]ff1lib.Cipher
}

// NewFF1GeneratorV4 builds a v4 generator; ciphers for common radices are
// pre-warmed to avoid first-request latency.
func NewFF1GeneratorV4(key []byte, keyVersion string) (*FF1GeneratorV4, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("empty FPE key")
	}
	g := &FF1GeneratorV4{
		key:        key,
		keyVersion: keyVersion,
		maxTLen:    64,
		ciphers:    make(map[int]ff1lib.Cipher),
	}
	for _, radix := range []int{10, 26, 36} {
		if _, err := g.cipherFor(radix); err != nil {
			return nil, fmt.Errorf("ff1 warm radix=%d: %w", radix, err)
		}
	}
	return g, nil
}

func (g *FF1GeneratorV4) KeyVersion() string { return g.keyVersion }

func (g *FF1GeneratorV4) cipherFor(radix int) (ff1lib.Cipher, error) {
	g.mu.RLock()
	if c, ok := g.ciphers[radix]; ok {
		g.mu.RUnlock()
		return c, nil
	}
	g.mu.RUnlock()

	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.ciphers[radix]; ok {
		return c, nil
	}
	c, err := ff1lib.NewCipher(radix, g.maxTLen, g.key, nil)
	if err != nil {
		return ff1lib.Cipher{}, fmt.Errorf("ff1 NewCipher(radix=%d): %w", radix, err)
	}
	g.ciphers[radix] = c
	return c, nil
}

// RandomTweak returns 16 bytes of CSPRNG output. Caller keeps it only in RAM —
// detokenize does not need it because DB holds the AES-GCM ciphertext.
func RandomTweak() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return b, nil
}

// deriveSegmentTweak binds a base tweak to a segment label so the same bytes
// never encrypt two different segments (e.g. email local vs domain).
func deriveSegmentTweak(base []byte, label string) []byte {
	h := hmac.New(sha256.New, base)
	h.Write([]byte(label))
	return h.Sum(nil)[:16]
}

// encryptDigits runs FF1 over a digit string 0-9 (radix 10).
func (g *FF1GeneratorV4) encryptDigits(plain string, tweak []byte) (string, error) {
	c, err := g.cipherFor(10)
	if err != nil {
		return "", err
	}
	return c.EncryptWithTweak(plain, tweak)
}

// canon26 is the library's canonical radix-26 alphabet: first 26 chars of
// "0123456789abcdefghijklmnopqrstuvwxyz" = "0123456789abcdefghijklmnop".
// We cannot just lower-case A-Z because q..z lie outside the library's
// radix-26 range. Instead we map letters A-Z <-> values 0..25 and render
// those values through canon26 for the FF1 call.
const canon26 = "0123456789abcdefghijklmnop"

// encryptLettersUpper runs FF1 at radix 26 over a string of uppercase
// letters. Each letter A-Z is mapped to its ordinal 0..25, written as a
// canon26 character for the cipher input, encrypted, then mapped back to
// A-Z from the ciphertext's canon26 value.
func (g *FF1GeneratorV4) encryptLettersUpper(plain string, tweak []byte) (string, error) {
	c, err := g.cipherFor(26)
	if err != nil {
		return "", err
	}
	in := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		ch := plain[i]
		if ch >= 'a' && ch <= 'z' {
			ch = ch - 'a' + 'A'
		}
		if ch < 'A' || ch > 'Z' {
			return "", fmt.Errorf("non-letter in PAN block: %q", plain)
		}
		in[i] = canon26[ch-'A']
	}
	ct, err := c.EncryptWithTweak(string(in), tweak)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i++ {
		idx := strings.IndexByte(canon26, ct[i])
		if idx < 0 {
			return "", fmt.Errorf("cipher output %q not in canon26", ct)
		}
		out[i] = byte('A' + idx)
	}
	return string(out), nil
}

// encryptAlnumLower runs FF1 over a lowercase 0-9 a-z string (radix 36).
func (g *FF1GeneratorV4) encryptAlnumLower(plain string, tweak []byte) (string, error) {
	c, err := g.cipherFor(36)
	if err != nil {
		return "", err
	}
	return c.EncryptWithTweak(strings.ToLower(plain), tweak)
}

// TokenizePAN encrypts the 5-letter prefix + last letter together as a
// 6-letter radix-26 block, and the middle 4 digits as a radix-10 block.
// Reassembly preserves the 5L4D1L PAN shape.
func (g *FF1GeneratorV4) TokenizePAN(normalized string, tweak []byte) (string, error) {
	if len(normalized) != 10 {
		return "", fmt.Errorf("PAN must be 10 chars")
	}
	letters := string(normalized[0]) + string(normalized[1]) + string(normalized[2]) +
		string(normalized[3]) + string(normalized[4]) + string(normalized[9])
	digits := normalized[5:9]

	ctLetters, err := g.encryptLettersUpper(letters, deriveSegmentTweak(tweak, "pan_letters"))
	if err != nil {
		return "", fmt.Errorf("ff1 pan letters: %w", err)
	}
	ctDigits, err := g.encryptDigits(digits, deriveSegmentTweak(tweak, "pan_digits"))
	if err != nil {
		return "", fmt.Errorf("ff1 pan digits: %w", err)
	}
	if len(ctLetters) != 6 || len(ctDigits) != 4 {
		return "", fmt.Errorf("unexpected cipher length")
	}
	return ctLetters[:5] + ctDigits + string(ctLetters[5]), nil
}

// cycleWalkMaxIter bounds the retry budget when constraining FF1 output to a
// subset of its radix domain. For digit constraints the probability of >N
// iterations is <=0.6^N, so 50 is astronomically safe (<1e-11 for MOBILE).
const cycleWalkMaxIter = 50

// TokenizeAADHAR encrypts all 12 digits as a single radix-10 block and cycle-
// walks until the first digit is non-zero (Aadhaar tokens must not start with
// '0' per UIDAI convention and per user requirement).
func (g *FF1GeneratorV4) TokenizeAADHAR(normalized string, tweak []byte) (string, error) {
	if len(normalized) != 12 {
		return "", fmt.Errorf("AADHAR must be 12 digits")
	}
	tw := deriveSegmentTweak(tweak, "aadhar")
	s := normalized
	for iter := 0; iter < cycleWalkMaxIter; iter++ {
		ct, err := g.encryptDigits(s, tw)
		if err != nil {
			return "", err
		}
		if ct[0] != '0' {
			return ct, nil
		}
		s = ct
	}
	return "", fmt.Errorf("aadhar cycle walk exhausted")
}

// TokenizeMobile encrypts the 10-digit mobile as a single radix-10 block and
// cycle-walks until the first digit is 6-9 (valid Indian mobile prefix).
func (g *FF1GeneratorV4) TokenizeMobile(normalized string, tweak []byte) (string, error) {
	if len(normalized) != 10 {
		return "", fmt.Errorf("mobile must be 10 digits")
	}
	tw := deriveSegmentTweak(tweak, "mobile")
	s := normalized
	for iter := 0; iter < cycleWalkMaxIter; iter++ {
		ct, err := g.encryptDigits(s, tw)
		if err != nil {
			return "", err
		}
		if ct[0] >= '6' && ct[0] <= '9' {
			return ct, nil
		}
		s = ct
	}
	return "", fmt.Errorf("mobile cycle walk exhausted")
}

// TokenizePassport handles the 1-letter + 7-digit Indian passport format.
// FF1 requires radix^len >= 100 (NIST 800-38G), so the single letter cannot
// use FF1 directly — it is shifted by a tweak-derived offset (keyed Caesar).
// The 7 digits are encrypted with FF1 radix 10.
func (g *FF1GeneratorV4) TokenizePassport(normalized string, tweak []byte) (string, error) {
	if len(normalized) != 8 {
		return "", fmt.Errorf("passport must be 8 chars")
	}
	letter := normalized[0]
	digits := normalized[1:]
	if letter < 'A' || letter > 'Z' {
		return "", fmt.Errorf("invalid passport letter")
	}

	shift := deriveSegmentTweak(tweak, "passport_letter")[0]
	outLetter := byte('A' + (int(letter-'A')+int(shift))%26)

	ctDigits, err := g.encryptDigits(digits, deriveSegmentTweak(tweak, "passport_digits"))
	if err != nil {
		return "", fmt.Errorf("ff1 passport digits: %w", err)
	}
	return string(outLetter) + ctDigits, nil
}

// TokenizeVoterID handles the Indian EPIC format: 3 uppercase letters (radix
// 26 via canon26 mapping) + 7 digits (radix 10). Letter and digit blocks are
// encrypted independently with per-segment tweaks. Output preserves the
// 3L7D shape so it remains a valid Voter ID.
func (g *FF1GeneratorV4) TokenizeVoterID(normalized string, tweak []byte) (string, error) {
	if len(normalized) != 10 {
		return "", fmt.Errorf("VOTERID must be 10 chars")
	}
	letters := normalized[0:3]
	digits := normalized[3:10]
	for i := 0; i < 3; i++ {
		c := letters[i]
		if c < 'A' || c > 'Z' {
			return "", fmt.Errorf("VOTERID letter prefix must be A-Z")
		}
	}
	for i := 0; i < 7; i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return "", fmt.Errorf("VOTERID digit suffix must be 0-9")
		}
	}

	ctLetters, err := g.encryptLettersUpper(letters, deriveSegmentTweak(tweak, "voterid_letters"))
	if err != nil {
		return "", fmt.Errorf("ff1 voterid letters: %w", err)
	}
	ctDigits, err := g.encryptDigits(digits, deriveSegmentTweak(tweak, "voterid_digits"))
	if err != nil {
		return "", fmt.Errorf("ff1 voterid digits: %w", err)
	}
	if len(ctLetters) != 3 || len(ctDigits) != 7 {
		return "", fmt.Errorf("unexpected cipher length")
	}
	return ctLetters + ctDigits, nil
}

// TokenizeDL treats the normalized DL (uppercase, separators stripped) as an
// alphanumeric block and encrypts it with FF1 radix 36 (0-9 a-z). Output is
// re-upper-cased; output positions no longer guarantee letter-vs-digit parity
// with the input (acceptable for DL since its format is regionally variable).
// First-character cycle walk guarantees the token does not start with '0'.
func (g *FF1GeneratorV4) TokenizeDL(normalized string, tweak []byte) (string, error) {
	if len(normalized) < 2 {
		return "", fmt.Errorf("DL too short for FF1")
	}
	tw := deriveSegmentTweak(tweak, "dl")
	s := normalized
	for iter := 0; iter < cycleWalkMaxIter; iter++ {
		ct, err := g.encryptAlnumLower(s, tw)
		if err != nil {
			return "", fmt.Errorf("ff1 dl: %w", err)
		}
		if ct[0] != '0' {
			return strings.ToUpper(ct), nil
		}
		s = ct
	}
	return "", fmt.Errorf("dl cycle walk exhausted")
}

// TokenizeEmail preserves @ and dots in the domain. The local part and each
// domain label are independently FF1-encrypted on the subset of their
// alphanumerics with a per-segment tweak. Non-alphanumeric punctuation is
// preserved in its original positions (e.g. '.', '-', '_', '+').
//
// Outer cycle walk: if the resulting token's first character would be '0',
// re-derive all per-segment tweaks under an iter-bound base tweak and retry.
// Prob('0' first char) <= 1/36 per attempt, so expected iters ~= 1.03.
func (g *FF1GeneratorV4) TokenizeEmail(normalized string, tweak []byte) (string, error) {
	at := strings.LastIndexByte(normalized, '@')
	if at <= 0 || at == len(normalized)-1 {
		return "", fmt.Errorf("invalid email format")
	}
	local := normalized[:at]
	domain := normalized[at+1:]

	for iter := 0; iter < cycleWalkMaxIter; iter++ {
		baseTweak := tweak
		if iter > 0 {
			baseTweak = deriveSegmentTweak(tweak, fmt.Sprintf("email_iter_%d", iter))
		}

		ctLocal, err := g.tokenizeEmailChunk(local, deriveSegmentTweak(baseTweak, "email_local"))
		if err != nil {
			return "", fmt.Errorf("ff1 email local: %w", err)
		}

		labels := strings.Split(domain, ".")
		for i, lbl := range labels {
			if lbl == "" {
				continue
			}
			segTweak := deriveSegmentTweak(baseTweak, fmt.Sprintf("email_domain_%d", i))
			ct, err := g.tokenizeEmailChunk(lbl, segTweak)
			if err != nil {
				return "", fmt.Errorf("ff1 email domain label %d: %w", i, err)
			}
			labels[i] = ct
		}
		result := ctLocal + "@" + strings.Join(labels, ".")

		// First char of full email token must not be '0'.
		if result[0] != '0' {
			return result, nil
		}
	}
	return "", fmt.Errorf("email cycle walk exhausted")
}

// tokenizeEmailChunk extracts alphanumerics as a lowercase string, encrypts
// with FF1 radix 36, and splices the result back into the original positions,
// preserving any punctuation. If fewer than 2 alphanumerics are present the
// FF1 minlen rule fails — we fall back to a keyed HMAC-based deterministic
// mapping for that chunk so small local parts still produce a valid token.
func (g *FF1GeneratorV4) tokenizeEmailChunk(s string, tweak []byte) (string, error) {
	positions := make([]int, 0, len(s))
	alnum := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			positions = append(positions, i)
			alnum = append(alnum, c)
		}
	}
	if len(alnum) == 0 {
		return s, nil
	}

	var ct string
	if len(alnum) < 2 {
		// FF1 minlen rule fails — keyed deterministic fallback.
		h := hmac.New(sha256.New, g.key)
		h.Write(tweak)
		h.Write(alnum)
		d := h.Sum(nil)
		alphabet := "0123456789abcdefghijklmnopqrstuvwxyz"
		out := make([]byte, len(alnum))
		for i := range out {
			out[i] = alphabet[int(d[i])%36]
		}
		ct = string(out)
	} else {
		var err error
		ct, err = g.encryptAlnumLower(string(alnum), tweak)
		if err != nil {
			return "", err
		}
	}

	out := []byte(s)
	for i, p := range positions {
		out[p] = ct[i]
	}
	return string(out), nil
}
