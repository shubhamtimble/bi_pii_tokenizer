package bi_internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"bi_pii_tokenizer/common"
)

type TokenizeV4Request struct {
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

type TokenizeV4Response struct {
	FPT     string `json:"fpt"`
	PIIType string `json:"pii_type"`
}

// v4MaxAttempts bounds the FPT-collision retry loop. Each attempt regenerates
// a random tweak, so in normal operation the first attempt succeeds; the
// retry slack exists for the birthday case on a very full table.
const v4MaxAttempts = 100

func (s *Server) tokenizeV4Handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := AuditEvent{Action: "tokenize", Version: "v4", IP: clientIP(r)}

	var req TokenizeV4Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, "invalid body", w)
		return
	}
	ev.PIIType = strings.ToUpper(strings.TrimSpace(req.PIIType))

	if s.ff1Gen == nil {
		s.auditFail(ev, start, http.StatusServiceUnavailable, "v4 FF1 generator not configured (set FPE_KEY_BASE64)", w)
		return
	}

	// whitelist of v4-supported types — anything else is "Invalid PII Type".
	// A known type whose value fails its format regex falls through to the
	// validator below and surfaces as "Invalid <TYPE> Format".
	switch ev.PIIType {
	case common.PIITypePAN, common.PIITypeAADHAR,
		common.PIITypeMobile, common.PIITypePhone,
		common.PIITypeEmail, common.PIITypeDL,
		common.PIITypePassport, common.PIITypeVoterID:
	default:
		s.auditFail(ev, start, http.StatusBadRequest, "Invalid PII Type", w)
		return
	}

	normalized, err := common.NormalizeAndValidateV4(req.PIIType, req.PIIValue)
	if err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, fmt.Sprintf("Invalid %s Format", ev.PIIType), w)
		return
	}

	fpt, err := s.TokenizeV4(r.Context(), ev.PIIType, normalized)
	if err != nil {
		log.Printf("tokenize_v4 error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.FPT = fpt
	ev.ValueHash = common.ValueHash(normalized)
	ev.Decision = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TokenizeV4Response{
		FPT:     fpt,
		PIIType: ev.PIIType,
	})
}

// TokenizeV4 implements the stateful vault flow for v4: the blind index
// deduplicates against an existing row (from any version — the vault is
// shared), and only on a true miss do we generate a new FF1 token with a
// fresh random tweak.
func (s *Server) TokenizeV4(ctx context.Context, piiType, normalized string) (string, error) {
	blind := common.HMACBlindIndex(s.hmacKey, normalized)

	if s.cache != nil {
		if fpt, err := s.cache.GetV4ByBlindIndex(ctx, blind); err == nil && fpt != "" {
			return fpt, nil
		}
	}

	if found, err := s.store.GetByBlindIndex(blind); err != nil {
		return "", fmt.Errorf("db lookup by blind: %w", err)
	} else if found != nil {
		s.cacheWriteThroughV4(ctx, found.DataType, blind, found.FPT, found.EncryptedValue)
		return found.FPT, nil
	}

	for attempt := 0; attempt < v4MaxAttempts; attempt++ {
		tweak, err := common.RandomTweak()
		if err != nil {
			return "", err
		}
		candidate, err := s.generateV4FPT(piiType, normalized, tweak)
		if err != nil {
			return "", err
		}

		existing, err := s.store.GetByFPT(candidate)
		if err != nil {
			return "", fmt.Errorf("db lookup by fpt: %w", err)
		}
		if existing != nil {
			if existing.BlindIndex == blind {
				s.cacheWriteThroughV4(ctx, existing.DataType, blind, existing.FPT, existing.EncryptedValue)
				return existing.FPT, nil
			}
			continue
		}

		encStr, err := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
		if err != nil {
			return "", fmt.Errorf("encrypt: %w", err)
		}
		encBytes := []byte(encStr)

		created, ierr := s.store.InsertToken(encBytes, blind, candidate, piiType)
		if ierr == nil && created != nil {
			s.cacheWriteThroughV4(ctx, piiType, blind, candidate, encBytes)
			return candidate, nil
		}

		// Race: re-check by blind (someone else inserted the same PII) then by
		// fpt (our candidate collided with a concurrent different PII). Either
		// way, retry with a new tweak if we can't resolve.
		if existingByBlind, berr := s.store.GetByBlindIndex(blind); berr == nil && existingByBlind != nil {
			s.cacheWriteThroughV4(ctx, existingByBlind.DataType, blind, existingByBlind.FPT, existingByBlind.EncryptedValue)
			return existingByBlind.FPT, nil
		}
		log.Printf("tokenize_v4: insert race candidate=%s err=%v (retry)", candidate, ierr)
	}
	return "", errors.New("unable to allocate unique token after max attempts")
}

// generateV4FPT dispatches to the PII-type-specific FF1 routine.
func (s *Server) generateV4FPT(piiType, normalized string, tweak []byte) (string, error) {
	switch piiType {
	case common.PIITypePAN:
		return s.ff1Gen.TokenizePAN(normalized, tweak)
	case common.PIITypeAADHAR:
		return s.ff1Gen.TokenizeAADHAR(normalized, tweak)
	case common.PIITypeMobile, common.PIITypePhone:
		return s.ff1Gen.TokenizeMobile(normalized, tweak)
	case common.PIITypeEmail:
		return s.ff1Gen.TokenizeEmail(normalized, tweak)
	case common.PIITypeDL:
		return s.ff1Gen.TokenizeDL(normalized, tweak)
	case common.PIITypePassport:
		return s.ff1Gen.TokenizePassport(normalized, tweak)
	case common.PIITypeVoterID:
		return s.ff1Gen.TokenizeVoterID(normalized, tweak)
	}
	return "", fmt.Errorf("unsupported pii_type: %s", piiType)
}

func (s *Server) cacheWriteThroughV4(ctx context.Context, dataType, blind, fpt string, enc []byte) {
	// single pipelined round-trip writes both blind→fpt and fpt→packed(type,enc)
	_ = s.cache.SetV4BlindAndFPT(ctx, dataType, blind, fpt, enc)
}

// auditFail writes the error response and emits a failure audit event.
// Intended for handler-level short-circuits (validation, config, decode).
// Suffixes ".failed" on the action so consumers can filter events by outcome
// just on action; sets decision="failure" for fine-grained query.
func (s *Server) auditFail(ev AuditEvent, start time.Time, status int, msg string, w http.ResponseWriter) {
	if ev.Action != "" && !strings.HasSuffix(ev.Action, ".failed") {
		ev.Action += ".failed"
	}
	ev.Decision = "failure"
	ev.Error = msg
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)
	writeJSONError(w, status, msg)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
