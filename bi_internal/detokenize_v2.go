package bi_internal

import (
	"encoding/json"
	"net/http"
	"strings"

	"bi_pii_tokenizer/common"
)

type DetokenizeV2Request struct {
	FPT string `json:"fpt"`
}

type DetokenizeV2Response struct {
	PIIValue string `json:"pii_value,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (s *Server) HandleDetokenizeV2(w http.ResponseWriter, r *http.Request) {

	var req DetokenizeV2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV2Err(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	req.FPT = strings.TrimSpace(req.FPT)
	if req.FPT == "" {
		writeV2Err(w, http.StatusBadRequest, "fpt is required")
		return
	}

	record, gerr := s.store.GetByFPT(req.FPT)
	if gerr != nil {
		writeV2Err(w, http.StatusInternalServerError, "db error: "+gerr.Error())
		return
	}
	if record == nil {
		writeV2Err(w, http.StatusNotFound, "token not found")
		return
	}

	// BYTEA → []byte
	encBytes := record.EncryptedValue
	if len(encBytes) == 0 {
		writeV2Err(w, http.StatusInternalServerError, "empty encrypted_value")
		return
	}

	// Convert bytes → base64 string for AES decrypt
	encStr := string(encBytes)

	// Declare variables BEFORE using "=" assignment
	var piiBytes []byte
	var derr error

	// Decrypt
	piiBytes, derr = common.AESGCMDecrypt(s.aesKey, encStr)
	if derr != nil {
		writeV2Err(w, http.StatusInternalServerError, "decrypt failed: "+derr.Error())
		return
	}

	json.NewEncoder(w).Encode(DetokenizeV2Response{
		PIIValue: string(piiBytes),
	})
}
