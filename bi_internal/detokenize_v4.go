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
	FPT      string `json:"fpt"`
	PIIType  string `json:"pii_type"`
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

	plain, dataType, err := s.DetokenizeV4(r.Context(), fpt)
	if err != nil {
		if err == ErrTokenNotFound {
			s.auditFail(ev, start, http.StatusNotFound, "token not found", w)
			return
		}
		log.Printf("detokenize_v4 error: %v", err)
		s.auditFail(ev, start, http.StatusInternalServerError, "internal error", w)
		return
	}
	ev.PIIType = dataType
	ev.Status = "success"
	ev.LatencyMS = time.Since(start).Milliseconds()
	s.audit.Log(ev)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DetokenizeV4Response{
		FPT:      fpt,
		PIIType:  dataType,
		PIIValue: plain,
	})
}

// DetokenizeV4 returns (plaintext, dataType, err). The cache value packs the
// data_type alongside the encrypted bytes so a hit returns both in one round.
// Old-format entries (no packed type) trigger DB fallback to recover the type.
func (s *Server) DetokenizeV4(ctx context.Context, fpt string) (string, string, error) {
	if s.cache != nil {
		if dt, enc, err := s.cache.GetV4ByFPT(ctx, fpt); err == nil && len(enc) > 0 && dt != "" {
			plain, derr := common.AESGCMDecrypt(s.aesKey, string(enc))
			if derr == nil {
				return string(plain), dt, nil
			}
			log.Printf("detokenize_v4: cache decrypt failed, falling back to DB: %v", derr)
		}
	}

	pt, err := s.store.GetByFPT(fpt)
	if err != nil {
		return "", "", err
	}
	if pt == nil {
		return "", "", ErrTokenNotFound
	}

	// async pipelined write-back — fire-and-forget on a background ctx
	if s.cache != nil {
		dataType := pt.DataType
		fptVal := pt.FPT
		blindIdx := pt.BlindIndex
		enc := pt.EncryptedValue
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.cache.SetV4BlindAndFPT(bgCtx, dataType, blindIdx, fptVal, enc)
		}()
	}

	plain, err := common.AESGCMDecrypt(s.aesKey, string(pt.EncryptedValue))
	if err != nil {
		return "", "", err
	}
	return string(plain), pt.DataType, nil
}
