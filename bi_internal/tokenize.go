package bi_internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"bi_pii_tokenizer/common"
)

type TokenizeRequest struct {
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

type TokenizeResponse struct {
	FPT string `json:"fpt"`
}
func isValidPAN(pan string) bool {
    pan = strings.ToUpper(strings.TrimSpace(pan))
    if len(pan) != 10 {
        return false
    }
    // Regex: 5 letters, 4 digits, 1 letter
    re := regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
    return re.MatchString(pan)
}

func isValidAADHAR(aadhar string) bool {
    aadhar = strings.TrimSpace(aadhar)
    if len(aadhar) != 12 {
        return false
    }

    // Must be exactly 12 digits
    re := regexp.MustCompile(`^[0-9]{12}$`)
    return re.MatchString(aadhar)
}

var (
    rePhone10Legacy  = regexp.MustCompile(`^[6-9][0-9]{9}$`)
    reEmailLegacy    = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
    rePassportLegacy = regexp.MustCompile(`^[A-Z][0-9]{7}$`)
    reNonDigitLegacy = regexp.MustCompile(`[^0-9]`)
)

func normalizeLegacyPhone(raw string) string {
    v := strings.TrimSpace(raw)
    v = strings.TrimPrefix(v, "+91")
    return reNonDigitLegacy.ReplaceAllString(v, "")
}

func isValidPhone(raw string) bool {
    return rePhone10Legacy.MatchString(normalizeLegacyPhone(raw))
}

func isValidEmail(raw string) bool {
    return reEmailLegacy.MatchString(strings.ToLower(strings.TrimSpace(raw)))
}

func isValidPassport(raw string) bool {
    return rePassportLegacy.MatchString(strings.ToUpper(strings.TrimSpace(raw)))
}

func (s *Server) tokenizeHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := AuditEvent{Action: "tokenize", Version: "v1", RemoteIP: clientIP(r)}

	var req TokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, "Invalid Body Keep PII Type and PII Value", w)
		return
	}
	req.PIIType = strings.ToUpper(strings.TrimSpace(req.PIIType))
	req.PIIValue = strings.TrimSpace(req.PIIValue)
	ev.PIIType = req.PIIType
	if req.PIIType == "" || req.PIIValue == "" {
		s.auditFail(ev, start, http.StatusBadRequest, "pii_type and pii_value are required", w)
		return
	}

	// whitelist of legacy-supported PII types — reject unknowns before any
	// generation logic so a typo'd or malicious pii_type can't slip into the
	// default base36 fallback path.
	switch req.PIIType {
	case "PAN", "AADHAR", "PHONE", "MOBILE", "EMAIL", "PASSPORT":
	default:
		s.auditFail(ev, start, http.StatusBadRequest, "Invalid PII Type", w)
		return
	}

	if req.PIIType == "PAN" {
		if !isValidPAN(req.PIIValue) {
			s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", req.PIIType), w)
			return
		}
	}

	if req.PIIType == "AADHAR" {
		if !isValidAADHAR(req.PIIValue) {
			s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", req.PIIType), w)
			return
		}
	}

	if req.PIIType == "PHONE" || req.PIIType == "MOBILE" {
		if !isValidPhone(req.PIIValue) {
			s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", req.PIIType), w)
			return
		}
	}

	if req.PIIType == "EMAIL" {
		if !isValidEmail(req.PIIValue) {
			s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", req.PIIType), w)
			return
		}
	}

	if req.PIIType == "PASSPORT" {
		if !isValidPassport(req.PIIValue) {
			s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", req.PIIType), w)
			return
		}
	}

	fpt, err := s.Tokenize(r.Context(), req.PIIType, req.PIIValue)
	if err != nil {
		log.Printf("tokenize error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.FPT = fpt
	ev.Status = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	log.Println("API Call SuccessFul")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenizeResponse{FPT: fpt})

}

// Tokenize creates or returns a format-preserving token (FPT) for given PII value.
// It is deterministic for the same PII (returns existing token if present) and
// will try alternate deterministic candidates when there is a collision.
func (s *Server) Tokenize(ctx context.Context, dataType, value string) (string, error) {
	var normalized string
	switch strings.ToUpper(strings.TrimSpace(dataType)) {
	case "PAN":
		normalized = strings.ToUpper(strings.TrimSpace(value))
	case "EMAIL":
		normalized = strings.ToLower(strings.TrimSpace(value))
	case "PASSPORT":
		normalized = strings.ToUpper(strings.TrimSpace(value))
	case "PHONE", "MOBILE":
		normalized = normalizeLegacyPhone(value)
	default:
		normalized = strings.TrimSpace(value)
	}
	blind := common.HMACBlindIndex(s.hmacKey, normalized)

	// 1) Cache lookup (blind -> fpt)
	if s.cache != nil {
		if fpt, err := s.cache.GetByBlindIndex(ctx, dataType, blind); err == nil && fpt != "" {
			log.Println("Tokenize", fpt)
			return fpt, nil // cache hit
		}
		// on cache error fallthrough to DB
	}

	// 2) DB lookup by blind index
	found, err := s.store.GetByBlindIndex(blind)
	if err != nil {
		return "", err
	}
	if found != nil {
		// write-back to cache (EncryptedValue is []byte in model)
		if s.cache != nil {
			_ = s.cache.SetByBlindIndex(ctx, dataType, blind, found.FPT)
			_ = s.cache.SetByFPT(ctx, dataType, found.FPT, found.EncryptedValue)
		}
		return found.FPT, nil
	}

	// 3) Not found -> allocate deterministically with retries
	const maxAttempts = 1000
	for counter := 0; counter < maxAttempts; counter++ {
		candidate, ferr := common.FPTFromBlindIndexWithCounter(blind, normalized, dataType, counter)
		if ferr != nil {
			return "", ferr
		}

		existing, gerr := s.store.GetByFPT(candidate)
		if gerr != nil {
			return "", gerr
		}

		if existing == nil {
			// encrypt returns string (base64 or b64-like). Convert to []byte only when inserting/caching.
			encStr, err := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
			if err != nil {
				return "", err
			}
			encBytes := []byte(encStr)

			created, ierr := s.store.InsertToken(encBytes, blind, candidate, dataType) // InsertToken expects []byte
			if ierr == nil && created != nil {
				// success — write-through cache (pass []byte)
				if s.cache != nil {
					_ = s.cache.SetByBlindIndex(ctx, dataType, blind, candidate)
					_ = s.cache.SetByFPT(ctx, dataType, candidate, encBytes)
				}
				return candidate, nil
			}
			// likely race — retry
			log.Printf("insert race or error for candidate %s: %v (retrying)", candidate, ierr)
			continue
		}

		// existing token found
		if existing.BlindIndex == blind {
			// same PII, write-back and return
			if s.cache != nil {
				_ = s.cache.SetByBlindIndex(ctx, dataType, blind, existing.FPT)
				_ = s.cache.SetByFPT(ctx, dataType, existing.FPT, existing.EncryptedValue)
			}
			return existing.FPT, nil
		}
		// collision with different PII -> next counter
		continue
	}
	return "", fmt.Errorf("unable to allocate unique token after %d attempts", maxAttempts)
}
