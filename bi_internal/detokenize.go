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
	FPT      string `json:"fpt"`
	PIIType  string `json:"pii_type"`
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
	ev.Status = "success"
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
