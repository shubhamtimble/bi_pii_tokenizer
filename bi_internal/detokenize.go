package bi_internal

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"bi_pii_tokenizer/common"
)

type DetokenizeRequest struct {
	FPT string `json:"fpt"`
}

type DetokenizeResponse struct {
	PIIValue string `json:"pii_value"`
}

func (s *Server) detokenizeHandler(w http.ResponseWriter, r *http.Request) {
	var req DetokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid Body Keep Token with Fpt key")
		return
	}
	req.FPT = strings.TrimSpace(req.FPT)
	if req.FPT == "" {
		writeJSONError(w, http.StatusBadRequest, "fpt required")
		return
	}
	val, err := s.Detokenize(r.Context(), req.FPT)
	if err != nil {
		if err == ErrTokenNotFound {
			writeJSONError(w, http.StatusNotFound, "token not found")
			return
		}
		log.Printf("detokenize error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
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
