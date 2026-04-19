package bi_internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"bi_pii_tokenizer/common"
)

// v3 request/response models
type TokenizeV3Request struct {
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

type TokenizeV3Response struct {
	FPT string `json:"fpt,omitempty"`
}


// Register routes (add these lines to Server.routes()):
// sr.HandleFunc("/v3/tokenize", s.tokenizeV3Handler).Methods("POST")
// sr.HandleFunc("/v3/detokenize", s.detokenizeV3Handler).Methods("POST")

// tokenizeV3Handler: public HTTP handler
func (s *Server) tokenizeV3Handler(w http.ResponseWriter, r *http.Request) {
	var req TokenizeV3Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	req.PIIType = strings.ToUpper(strings.TrimSpace(req.PIIType))
	req.PIIValue = strings.TrimSpace(req.PIIValue)

	if req.PIIType == "" || req.PIIValue == "" {
		writeJSONError(w, http.StatusBadRequest, "pii_type and pii_value are required")
		return
	}

	// basic validation
	if req.PIIType == "PAN" {
		if !isValidPAN(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "invalid PAN format")
			return
		}
	}
	if req.PIIType == "AADHAR" {
		if !isValidAADHAR(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "invalid AADHAR format")
			return
		}
	}
	if req.PIIType == "PHONE" {
		if !isValidPhone(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "invalid PHONE format")
			return
		}
	}
	if req.PIIType == "EMAIL" {
		if !isValidEmail(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "invalid EMAIL format")
			return
		}
	}

	fpt, err := s.TokenizeV3(r.Context(), req.PIIType, req.PIIValue)
	if err != nil {
		log.Printf("tokenize_v3 error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenizeV3Response{FPT: fpt})
}

// TokenizeV3: FF1 tokenization + persistence
func (s *Server) TokenizeV3(ctx context.Context, dataType, value string) (string, error) {
	// normalize
	var normalized string
	if strings.ToUpper(strings.TrimSpace(dataType)) == "PAN" {
		normalized = strings.ToUpper(strings.TrimSpace(value))
	} else if strings.ToUpper(strings.TrimSpace(dataType)) == "EMAIL" {
		normalized = strings.ToLower(strings.TrimSpace(value))
	} else if strings.ToUpper(strings.TrimSpace(dataType)) == "PHONE" {
		// Just trim. Verification ensures it's 10 digits
		normalized = strings.TrimSpace(value)
	} else {
		normalized = strings.TrimSpace(value)
	}

	// blind (hex) for DB lookups
	blind := common.HMACBlindIndex(s.hmacKey, normalized)
	blindHex := blind

	// 1) cache by type+blind
	cacheKeyPrefix := strings.ToUpper(dataType)
	if s.cache != nil {
		if fpt, err := s.cache.GetByBlindIndex(ctx, cacheKeyPrefix, blindHex); err == nil && fpt != "" {
			return fpt, nil
		}
	}

	// 2) DB lookup by blind
	found, err := s.store.GetByBlindIndexV3(blindHex)
	if err != nil {
		return "", fmt.Errorf("db error: %w", err)
	}
	if found != nil {
		// cache write-back
		if s.cache != nil {
			_ = s.cache.SetByBlindIndex(ctx, cacheKeyPrefix, blindHex, found.FPT)
			_ = s.cache.SetByFPT(ctx, cacheKeyPrefix, found.FPT, found.EncryptedValue)
		}
		return found.FPT, nil
	}

	// 3) Prepare FF1 generator
	var gen *common.FF1Generator
	if s.fptGen != nil {
		gen = s.fptGen
	}
	if gen == nil {
		fpeB64 := os.Getenv("FPE_KEY_BASE64")
		if fpeB64 == "" {
			return "", fmt.Errorf("FPE_KEY_BASE64 is required (env)")
		}
		keyBytes, err := common.DecodeBase64Key(fpeB64)
		if err != nil {
			return "", fmt.Errorf("invalid FPE key: %w", err)
		}
		keyVer := os.Getenv("FPE_KEY_VERSION")
		if keyVer == "" {
			keyVer = "v1"
		}
		fg, ferr := common.NewFF1Generator(keyBytes, keyVer)
		if ferr != nil {
			return "", fmt.Errorf("failed to create ff1 generator: %w", ferr)
		}
		gen = fg
	}

	// 4) build tweak
	keyVersion := gen.KeyVersion()
	tweak := []byte(strings.ToUpper(dataType) + ":" + keyVersion)

	// 5) generate FPT (bijective)
	fpt, gerr := gen.GenerateToken(ctx, dataType, normalized, tweak)
	if gerr != nil {
		return "", fmt.Errorf("ff1 generate error: %w", gerr)
	}

	// 6) encrypt plaintext for storage (AES-GCM returns base64 string in common helper)
	encB64, err := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
	if err != nil {
		return "", fmt.Errorf("encrypt error: %w", err)
	}
	// decode base64 to raw bytes for BYTEA column
	encBytes, derr := base64.StdEncoding.DecodeString(encB64)
	if derr != nil {
		return "", fmt.Errorf("invalid ciphertext base64: %w", derr)
	}

	// 7) insert into DB
	created, ierr := s.store.InsertTokenV3(encBytes, blindHex, fpt, dataType, keyVersion)
	if ierr != nil {
		// Real DB error — fallback selects
		log.Printf("insert error: %v", ierr)
		if existing, gerr := s.store.GetByFPTV3(fpt); gerr == nil && existing != nil {
			if s.cache != nil {
				_ = s.cache.SetByBlindIndex(ctx, cacheKeyPrefix, blindHex, existing.FPT)
				_ = s.cache.SetByFPT(ctx, cacheKeyPrefix, existing.FPT, existing.EncryptedValue)
			}
			return existing.FPT, nil
		}
		if existingByBlind, berr := s.store.GetByBlindIndexV3(blindHex); berr == nil && existingByBlind != nil {
			if s.cache != nil {
				_ = s.cache.SetByBlindIndex(ctx, cacheKeyPrefix, blindHex, existingByBlind.FPT)
				_ = s.cache.SetByFPT(ctx, cacheKeyPrefix, existingByBlind.FPT, existingByBlind.EncryptedValue)
			}
			return existingByBlind.FPT, nil
		}
		return "", fmt.Errorf("insert failed: %w", ierr)
	}

	// created == nil => ON CONFLICT DO NOTHING (someone else inserted)
	if created == nil {
		if existingByBlind, berr := s.store.GetByBlindIndexV3(blindHex); berr == nil && existingByBlind != nil {
			if s.cache != nil {
				_ = s.cache.SetByBlindIndex(ctx, cacheKeyPrefix, blindHex, existingByBlind.FPT)
				_ = s.cache.SetByFPT(ctx, cacheKeyPrefix, existingByBlind.FPT, existingByBlind.EncryptedValue)
			}
			return existingByBlind.FPT, nil
		}
		return "", fmt.Errorf("insert conflict: token exists but select returned nothing")
	}

	// success: created != nil
	if s.cache != nil {
		_ = s.cache.SetByBlindIndex(ctx, cacheKeyPrefix, blindHex, created.FPT)
		_ = s.cache.SetByFPT(ctx, cacheKeyPrefix, created.FPT, created.EncryptedValue)
	}
	return created.FPT, nil
}
// 	if err != nil {
// 		return "", fmt.Errorf("db error: %w", err)
// 	}
// 	if found == nil {
// 		return "", fmt.Errorf("not found")
// 	}
// 	plainBytes, derr := common.AESGCMDecrypt(s.aesKey, string(found.EncryptedValue))
// 	if derr != nil {
// 		return "", fmt.Errorf("decrypt failed: %w", derr)
// 	}
// 	return string(plainBytes), nil
// }
