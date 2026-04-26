package bi_internal

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"bi_pii_tokenizer/common"
)

type DetokenizeV4Request struct {
	FPT string `json:"fpt"`
}

type DetokenizeV4Response struct {
	PIIValue string `json:"pii_value"`
}

func (s *Server) detokenizeV4Handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := AuditEvent{Action: "detokenize", Version: "v4", RemoteIP: clientIP(r)}

	var req DetokenizeV4Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, "invalid body", w)
		return
	}
	fpt := strings.TrimSpace(req.FPT)
	if fpt == "" {
		s.auditFail(ev, start, http.StatusBadRequest, "fpt required", w)
		return
	}
	ev.FPT = fpt

	plain, err := s.DetokenizeV4(r.Context(), fpt)
	if err != nil {
		if err == ErrTokenNotFound {
			s.auditFail(ev, start, http.StatusNotFound, "token not found", w)
			return
		}
		log.Printf("detokenize_v4 error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.Status = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DetokenizeV4Response{PIIValue: plain})
}

// DetokenizeV4 recovers the plaintext PII by looking up the vault row for the
// FPT and AES-GCM-decrypting the stored envelope. Cache is queried first
// with a data-type-agnostic v4 key so a single Redis round-trip suffices.
func (s *Server) DetokenizeV4(ctx context.Context, fpt string) (string, error) {
	if s.cache != nil {
		if enc, err := s.cache.GetV4ByFPT(ctx, fpt); err == nil && enc != "" {
			plain, derr := common.AESGCMDecrypt(s.aesKey, enc)
			if derr == nil {
				return string(plain), nil
			}
			log.Printf("detokenize_v4: cache decrypt failed, falling back to DB: %v", derr)
		}
	}

	pt, err := s.store.GetByFPT(fpt)
	if err != nil {
		return "", err
	}
	if pt == nil {
		return "", ErrTokenNotFound
	}

	if s.cache != nil {
		_ = s.cache.SetV4ByFPT(ctx, pt.FPT, pt.EncryptedValue)
		_ = s.cache.SetV4ByBlindIndex(ctx, pt.BlindIndex, pt.FPT)
	}

	plain, err := common.AESGCMDecrypt(s.aesKey, string(pt.EncryptedValue))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
