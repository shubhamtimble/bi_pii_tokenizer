package bi_internal

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"bi_pii_tokenizer/common"
)

type DetokenizeRequest struct {
	FPT    string `json:"fpt"`
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

type DetokenizeResponse struct {
	FPT      string `json:"fpt"`
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

func (s *Server) detokenizeHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := AuditEvent{Action: "detokenize", Version: "v1", IP: clientIP(r)}

	var req DetokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, "Invalid Body Keep Token with Fpt key", w)
		return
	}
	req.FPT = strings.TrimSpace(req.FPT)
	req.Actor = strings.TrimSpace(req.Actor)
	req.Reason = strings.TrimSpace(req.Reason)
	ev.Actor = req.Actor
	ev.Reason = req.Reason
	if req.FPT == "" {
		s.auditFail(ev, start, http.StatusBadRequest, "fpt required", w)
		return
	}
	if req.Actor == "" || req.Reason == "" {
		s.auditFail(ev, start, http.StatusBadRequest, "actor and reason are required", w)
		return
	}
	ev.FPT = req.FPT

	// RBAC-enabled path fully owns the response: resolve the token's authoritative
	// data_type WITHOUT decrypting, gate on the (role, pii_type) permission, and
	// only decrypt when access is MASKED/FULL. NONE is denied before any decrypt.
	if s.rbac != nil && s.rbac.enabled {
		s.detokenizeWithRBAC(w, r, ev, start, req.FPT)
		return
	}

	val, dataType, err := s.Detokenize(r.Context(), req.FPT)
	if err != nil {
		if err == ErrTokenNotFound {
			s.auditFail(ev, start, http.StatusNotFound, "token not found", w)
			return
		}
		log.Printf("detokenize error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.PIIType = dataType
	ev.ValueHash = common.ValueHash(val)
	ev.Decision = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	json.NewEncoder(w).Encode(DetokenizeResponse{
		FPT:      req.FPT,
		PIIType:  dataType,
		PIIValue: val,
	})
}

var ErrTokenNotFound = errors.New("token not found")

// Detokenize returns (plaintext, dataType, err). dataType comes either from
// the packed cache value (cache hit) or from the DB row (cache miss). On a
// cache hit with an old-format entry (no packed type), we fall through to DB
// to recover the type and re-cache in the new format.
func (s *Server) Detokenize(ctx context.Context, fpt string) (string, string, error) {
	if strings.TrimSpace(fpt) == "" {
		return "", "", ErrTokenNotFound
	}

	// 1) cache lookup fpt → (dataType, encrypted_value)
	if s.cache != nil {
		if dt, enc, err := s.cache.GetByFPT(ctx, fpt); err == nil && len(enc) > 0 && dt != "" {
			plain, derr := common.AESGCMDecrypt(s.aesKey, string(enc))
			if derr != nil {
				return "", "", derr
			}
			return string(plain), dt, nil
		}
		// cache miss OR old-format entry (no type) → fall through to DB
	}

	// 2) DB lookup
	pt, err := s.store.GetByFPT(fpt)
	if err != nil {
		return "", "", err
	}
	if pt == nil {
		return "", "", ErrTokenNotFound
	}

	// async write-back to cache — fire-and-forget pipelined SET
	if s.cache != nil {
		dataType := pt.DataType
		fptVal := pt.FPT
		blindIdx := pt.BlindIndex
		enc := pt.EncryptedValue
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.cache.SetBlindAndFPT(bgCtx, dataType, blindIdx, fptVal, enc)
		}()
	}

	plain, err := common.AESGCMDecrypt(s.aesKey, string(pt.EncryptedValue))
	if err != nil {
		return "", "", err
	}
	return string(plain), pt.DataType, nil
}

// lookupForDetokenize resolves an fpt to its (dataType, encryptedValue) using the
// same cache→DB path as Detokenize but WITHOUT decrypting, so the RBAC gate can
// deny NONE access before any decryption. The cache namespace is unified across
// v1/v4, so this serves both detokenize handlers.
func (s *Server) lookupForDetokenize(ctx context.Context, fpt string) (string, []byte, error) {
	if strings.TrimSpace(fpt) == "" {
		return "", nil, ErrTokenNotFound
	}
	if s.cache != nil {
		if dt, enc, err := s.cache.GetByFPT(ctx, fpt); err == nil && len(enc) > 0 && dt != "" {
			return dt, enc, nil
		}
	}
	pt, err := s.store.GetByFPT(fpt)
	if err != nil {
		return "", nil, err
	}
	if pt == nil {
		return "", nil, ErrTokenNotFound
	}
	// best-effort async cache write-back, mirroring Detokenize
	if s.cache != nil {
		dataType := pt.DataType
		fptVal := pt.FPT
		blindIdx := pt.BlindIndex
		enc := pt.EncryptedValue
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.cache.SetBlindAndFPT(bgCtx, dataType, blindIdx, fptVal, enc)
		}()
	}
	return pt.DataType, pt.EncryptedValue, nil
}

// detokenizeWithRBAC handles a detokenize request when the permission layer is
// enabled. Shared by the v1 and v4 handlers (vault + cache are unified). It owns
// the full HTTP response and the audit event. The (role, pii_type) permission is
// evaluated on the authoritative vault data_type; NONE is denied before decrypt.
func (s *Server) detokenizeWithRBAC(w http.ResponseWriter, r *http.Request, ev AuditEvent, start time.Time, fpt string) {
	role := roleFromContext(r.Context())
	ev.RoleCode = role

	dataType, enc, lerr := s.lookupForDetokenize(r.Context(), fpt)
	if lerr != nil {
		if lerr == ErrTokenNotFound {
			s.auditFail(ev, start, http.StatusNotFound, "token not found", w)
			return
		}
		log.Printf("detokenize lookup error: %v", lerr)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.PIIType = dataType

	access, maskChar, expired, found, perr := s.rbac.GetDetokenizeAccess(r.Context(), role, dataType)
	if perr != nil {
		log.Printf("rbac detokenize check error: %v", perr)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	if expired {
		s.auditDeny(ev, start, http.StatusForbidden, "expired", "permission expired", w)
		return
	}
	if !found || access == AccessNone {
		s.auditDeny(ev, start, http.StatusForbidden, "denied", "not permitted", w)
		return
	}

	plain, derr := common.AESGCMDecrypt(s.aesKey, string(enc))
	if derr != nil {
		log.Printf("detokenize decrypt error: %v", derr)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}

	out := string(plain)
	decision := "success"
	if access == AccessMasked {
		out = MaskPII(dataType, out, maskChar)
		decision = "masked"
	}

	ev.ValueHash = common.ValueHash(string(plain)) // hash the real value, not the masked one
	ev.Decision = decision
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DetokenizeResponse{
		FPT:      fpt,
		PIIType:  dataType,
		PIIValue: out,
	})
}
