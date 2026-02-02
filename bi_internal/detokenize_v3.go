package bi_internal

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"

    "bi_pii_tokenizer/common"
)

/* ---------------------- Request / Response Structs ---------------------- */

type DetokenizeV3Request struct {
    FPT      string `json:"fpt"`
}

type DetokenizeV3Response struct {
    Plain string `json:"plain,omitempty"`
    Error string `json:"error,omitempty"`
}

/* -------------------------- Public HTTP Handler ------------------------- */

func (s *Server) detokenizeV3Handler(w http.ResponseWriter, r *http.Request) {

    var req DetokenizeV3Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeV3Err(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
        return
    }

    fpt := strings.TrimSpace(req.FPT)
    if fpt == "" {
        writeV3Err(w, http.StatusBadRequest, "fpt is required")
        return
    }

    plain, err := s.DetokenizeV3(r.Context(), fpt)
    if err != nil {
        writeV3Err(w, http.StatusBadRequest, err.Error())
        return
    }

    json.NewEncoder(w).Encode(DetokenizeV3Response{Plain: plain})
}

/* ---------------------- Core Server Logic ---------------------- */

func (s *Server) DetokenizeV3(ctx context.Context, fpt string) (string, error) {

    row, err := s.store.GetByFPTV3(fpt)
    if err != nil {
        return "", fmt.Errorf("db error: %w", err)
    }
    if row != nil {
        return decryptEncryptedValueBytes(s, row.EncryptedValue)
    }

    return "", fmt.Errorf("not found")
}

/* ------------------------------- Helpers -------------------------------- */

/* Robust decryption that handles raw BYTEA or base64 text */
func decryptEncryptedValueBytes(s *Server, encBytes []byte) (string, error) {

    // Try direct: the DB may contain base64 plaintext bytes
    plain, err := common.AESGCMDecrypt(s.aesKey, string(encBytes))
    if err == nil {
        return string(plain), nil
    }

    // Try re-base64-encoding raw bytes
    encoded := base64.StdEncoding.EncodeToString(encBytes)
    plain2, err2 := common.AESGCMDecrypt(s.aesKey, encoded)
    if err2 == nil {
        return string(plain2), nil
    }

    return "", fmt.Errorf("decrypt failed: %v / %v", err, err2)
}

/* JSON error writer */
func writeV3Err(w http.ResponseWriter, code int, msg string) {
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
