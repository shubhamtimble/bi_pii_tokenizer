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
	FPT string `json:"fpt"`
}

type DetokenizeResponse struct {
	PIIValue string `json:"pii_value"`
}

func (s *Server) detokenizeHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := AuditEvent{Action: "detokenize", Version: "v1", RemoteIP: clientIP(r)}

	var req DetokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditFail(ev, start, http.StatusBadRequest, "Invalid Body Keep Token with Fpt key", w)
		return
	}
	req.FPT = strings.TrimSpace(req.FPT)
	if req.FPT == "" {
		s.auditFail(ev, start, http.StatusBadRequest, "fpt required", w)
		return
	}
	ev.FPT = req.FPT
	val, err := s.Detokenize(r.Context(), req.FPT)
	if err != nil {
		if err == ErrTokenNotFound {
			s.auditFail(ev, start, http.StatusNotFound, "token not found", w)
			return
		}
		log.Printf("detokenize error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.Status = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	json.NewEncoder(w).Encode(DetokenizeResponse{PIIValue: val})
}

var ErrTokenNotFound = errors.New("token not found")

func (s *Server) Detokenize(ctx context.Context, fpt string) (string, error) {
	if strings.TrimSpace(fpt) == "" {
		return "", ErrTokenNotFound
	}

	// 1) cache lookup fpt -> encrypted_value
	if s.cache != nil {
		if encStr, err := s.cache.GetByFPT(ctx, "PAN", fpt); err == nil && encStr != "" {
			plain, derr := common.AESGCMDecrypt(s.aesKey, encStr)
			if derr != nil {
				return "", derr
			}
			return string(plain), nil
		}
		// on cache error fallthrough
	}

	// 2) DB lookup
	pt, err := s.store.GetByFPT(fpt)
	if err != nil {
		return "", err
	}
	if pt == nil {
		return "", ErrTokenNotFound
	}

	// write-back to cache
	if s.cache != nil {
		_ = s.cache.SetByFPT(ctx, pt.DataType, pt.FPT, pt.EncryptedValue)
		_ = s.cache.SetByBlindIndex(ctx, pt.DataType, pt.BlindIndex, pt.FPT)
	}

	plain, err := common.AESGCMDecrypt(s.aesKey, string(pt.EncryptedValue))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
