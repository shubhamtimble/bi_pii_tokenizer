package bi_internal

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"bi_pii_tokenizer/common"
)

type TokenizeV2Request struct {
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

type TokenizeV2Response struct {
	FPT   string `json:"fpt,omitempty"`
	Error string `json:"error,omitempty"`
}

func (s *Server) HandleTokenizeV2(w http.ResponseWriter, r *http.Request) {

	var req TokenizeV2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV2Err(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	req.PIIType = strings.ToUpper(strings.TrimSpace(req.PIIType))
	req.PIIValue = strings.TrimSpace(req.PIIValue)

	if req.PIIType == "" || req.PIIValue == "" {
		writeV2Err(w, http.StatusBadRequest, "pii_type and pii_value are required")
		return
	}

	// Normalize using existing logic
	normalized, nerr := common.NormalizePII(req.PIIValue, req.PIIType)
	if nerr != nil {
		writeV2Err(w, http.StatusBadRequest, nerr.Error())
		return
	}

	// Blind index (raw bytes)
	blindBytes := common.ComputeBlindIndex(s.hmacKey, normalized)

	// Convert blind index to HEX (safe for PostgreSQL TEXT)
	blindHex := hex.EncodeToString(blindBytes)

	// Deterministic FPT
	fpt, ferr := common.FPTDeterministic(blindBytes, normalized, req.PIIType)
	if ferr != nil {
		writeV2Err(w, http.StatusInternalServerError, ferr.Error())
		return
	}

	// Check DB for existing token
	existing, gerr := s.store.GetByFPT(fpt)
	if gerr != nil {
		writeV2Err(w, http.StatusInternalServerError, "db error: "+gerr.Error())
		return
	}

	if existing != nil {
		if existing.BlindIndex == blindHex {
			json.NewEncoder(w).Encode(TokenizeV2Response{FPT: fpt})
			return
		}
		// Blind index mismatch → shouldn't happen
		writeV2Err(w, http.StatusConflict, "unexpected token conflict")
		return
	}

	// Encrypt using AES-GCM → returns []byte
	encStr, encErr := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
	if encErr != nil {
		writeV2Err(w, http.StatusInternalServerError, "encryption failed: "+encErr.Error())
		return
	}

	// Base64 encode ciphertext → safe UTF-8 for PostgreSQL
	encBytes := []byte(encStr)
	
	// Insert new token
	created, ierr := s.store.InsertToken(encBytes, blindHex, fpt, req.PIIType)
	if ierr != nil || created == nil {
		writeV2Err(w, http.StatusInternalServerError, "insert failed: "+ierr.Error())
		return
	}

	json.NewEncoder(w).Encode(TokenizeV2Response{FPT: fpt})
}

func writeV2Err(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
