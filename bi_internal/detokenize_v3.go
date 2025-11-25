package bi_internal

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "os"

    "bi_pii_tokenizer/common"
)

/* ---------------------- Request / Response Structs ---------------------- */

type DetokenizeV3Request struct {
    FPT      string `json:"fpt"`
    TenantID string `json:"tenant_id,omitempty"`
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

    tenantID := getTenantIDFromPayload(req.TenantID)

    plain, err := s.DetokenizeV3(r.Context(), tenantID, fpt)
    if err != nil {
        writeV3Err(w, http.StatusBadRequest, err.Error())
        return
    }

    json.NewEncoder(w).Encode(DetokenizeV3Response{Plain: plain})
}

/* ---------------------- Core Server Logic (Tenant Aware) ---------------------- */

func (s *Server) DetokenizeV3(ctx context.Context, tenantID, fpt string) (string, error) {

    // 1) Try tenant-specific token
    row, err := s.store.GetByFPTTenant(tenantID, fpt)
    if err != nil {
        return "", fmt.Errorf("db error: %w", err)
    }
    if row != nil {
        return decryptEncryptedValueBytes(s, row.EncryptedValue)
    }

    // 2) If tenant missing → try global fallback
    if os.Getenv("V3_ALLOW_GLOBAL_FALLBACK") != "false" {
        globalRow, gerr := s.store.GetByFPTTenant("", fpt)
        if gerr != nil {
            return "", fmt.Errorf("db error: %w", gerr)
        }
        if globalRow != nil {
            return decryptEncryptedValueBytes(s, globalRow.EncryptedValue)
        }
    }

    return "", fmt.Errorf("not found")
}

/* ------------------------------- Helpers -------------------------------- */

/* Tenant ID selection */
func getTenantIDFromPayload(payloadTenant string) string {
    tenant := strings.TrimSpace(payloadTenant)
    if tenant != "" {
        return tenant
    }
    envTenant := strings.TrimSpace(os.Getenv("DEFAULT_TENANT_ID"))
    if envTenant != "" {
        return envTenant
    }
    return "" // global tenant
}

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
