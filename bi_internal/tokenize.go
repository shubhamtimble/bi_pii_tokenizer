package bi_internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"bi_pii_tokenizer/common"
)

type TokenizeRequest struct {
	PIIType  string `json:"pii_type"`
	PIIValue string `json:"pii_value"`
}

type TokenizeResponse struct {
	FPT string `json:"fpt"`
}
func isValidPAN(pan string) bool {
    pan = strings.ToUpper(strings.TrimSpace(pan))
    if len(pan) != 10 {
        return false
    }
    // Regex: 5 letters, 4 digits, 1 letter
    re := regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
    return re.MatchString(pan)
}

func isValidAADHAR(aadhar string) bool {
    aadhar = strings.TrimSpace(aadhar)
    if len(aadhar) != 12 {
        return false
    }

    // Must be exactly 12 digits
    re := regexp.MustCompile(`^[0-9]{12}$`)
    return re.MatchString(aadhar)
}

func (s *Server) tokenizeHandler(w http.ResponseWriter, r *http.Request) {
	var req TokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid Body Keep PII Type and PII Value")
		return
	}
	req.PIIType = strings.ToUpper(strings.TrimSpace(req.PIIType))
	req.PIIValue = strings.TrimSpace(req.PIIValue)
	if req.PIIType == "" || req.PIIValue == "" {
		writeJSONError(w, http.StatusBadRequest, "pii_type and pii_value are required")
		return
	}

	if req.PIIType == "PAN" {
		if !isValidPAN(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "Invalid PAN format")
			return
		}
	}

	if req.PIIType == "AADHAR" {
		if !isValidAADHAR(req.PIIValue) {
			writeJSONError(w, http.StatusBadRequest, "Invalid AADHAR format")
			return
		}
	}

	fpt, err := s.Tokenize(r.Context(), req.PIIType, req.PIIValue)
	if err != nil {
		log.Printf("tokenize error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	log.Println("API Call SuccessFul")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenizeResponse{FPT: fpt})

}

// Tokenize creates or returns a format-preserving token (FPT) for given PII value.
// It is deterministic for the same PII (returns existing token if present) and
// will try alternate deterministic candidates when there is a collision.



// func (s *Server) Tokenize(ctx context.Context, dataType, value string) (string, error) {
// 	var normalized string
// 	if strings.ToUpper(strings.TrimSpace(dataType)) == "PAN" {
// 		normalized = strings.ToUpper(strings.TrimSpace(value))
// 	} else {
// 		normalized = strings.TrimSpace(value)
// 	}
// 	blind := common.HMACBlindIndex(s.hmacKey, normalized)

// 	// 1) Cache lookup (blind -> fpt)
// 	if s.cache != nil {
// 		if fpt, err := s.cache.GetByBlindIndex(ctx, dataType, blind); err == nil && fpt != "" {
// 			log.Println("Tokenize", fpt)
// 			return fpt, nil // cache hit
// 		}
// 		// on cache error fallthrough to DB
// 	}

// 	// 2) DB lookup by blind index
// 	found, err := s.store.GetByBlindIndex(blind)
// 	if err != nil {
// 		return "", err
// 	}
// 	if found != nil {
// 		// write-back to cache (EncryptedValue is []byte in model)
// 		if s.cache != nil {
// 			_ = s.cache.SetByBlindIndex(ctx, dataType, blind, found.FPT)
// 			_ = s.cache.SetByFPT(ctx, dataType, found.FPT, found.EncryptedValue)
// 		}
// 		return found.FPT, nil
// 	}

// 	// 3) Not found -> allocate deterministically with retries
// 	const maxAttempts = 5000
// 	for counter := 0; counter < maxAttempts; counter++ {
// 		candidate, ferr := common.FPTFromBlindIndexWithCounter(blind, normalized, dataType, counter)
// 		if ferr != nil {
// 			return "", ferr
// 		}

// 		existing, gerr := s.store.GetByFPT(candidate)
// 		if gerr != nil {
// 			return "", gerr
// 		}

// 		if existing == nil {
// 			// encrypt returns string (base64 or b64-like). Convert to []byte only when inserting/caching.
// 			encStr, err := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
// 			if err != nil {
// 				return "", err
// 			}
// 			encBytes := []byte(encStr)

// 			created, ierr := s.store.InsertToken(encBytes, blind, candidate, dataType) // InsertToken expects []byte
// 			if ierr == nil && created != nil {
// 				// success — write-through cache (pass []byte)
// 				if s.cache != nil {
// 					_ = s.cache.SetByBlindIndex(ctx, dataType, blind, candidate)
// 					_ = s.cache.SetByFPT(ctx, dataType, candidate, encBytes)
// 				}
// 				return candidate, nil
// 			}
// 			// likely race — retry
// 			log.Printf("insert race or error for candidate %s: %v (retrying)", candidate, ierr)
// 			continue
// 		}

// 		// existing token found
// 		if existing.BlindIndex == blind {
// 			// same PII, write-back and return
// 			if s.cache != nil {
// 				_ = s.cache.SetByBlindIndex(ctx, dataType, blind, existing.FPT)
// 				_ = s.cache.SetByFPT(ctx, dataType, existing.FPT, existing.EncryptedValue)
// 			}
// 			return existing.FPT, nil
// 		}
// 		// collision with different PII -> next counter
// 		continue
// 	}
// 	return "", fmt.Errorf("unable to allocate unique token after %d attempts", maxAttempts)
// }


// in bi_internal/tokenize.go - replace the Tokenize method with this
func (s *Server) Tokenize(ctx context.Context, dataType, value string) (string, error) {
    // normalization
    var normalized string
    if strings.ToUpper(strings.TrimSpace(dataType)) == "PAN" {
        normalized = strings.ToUpper(strings.TrimSpace(value))
    } else {
        normalized = strings.TrimSpace(value)
    }

    blind := common.HMACBlindIndex(s.hmacKey, normalized)

    // 1) try cache by blind
    if s.cache != nil {
        if fpt, err := s.cache.GetByBlindIndex(ctx, dataType, blind); err == nil && fpt != "" {
            return fpt, nil
        }
        // on cache error fallthrough to DB
    }

    // 2) DB lookup by blind
    found, err := s.store.GetByBlindIndex(blind)
    if err != nil {
        return "", err
    }
    if found != nil {
        // write-back to cache
        if s.cache != nil {
            _ = s.cache.SetByBlindIndex(ctx, dataType, blind, found.FPT)
            _ = s.cache.SetByFPT(ctx, dataType, found.FPT, found.EncryptedValue)
        }
        return found.FPT, nil
    }

    // 3) Not found -> generate token using active generator
    var fpt string
    if s.fptGen == nil {
        return "", fmt.Errorf("fpt generator not configured on server")
    }

    var genErr error
    if s.fptGen.Mode() == "current" {
        // current generator expects blindHex as tweak/input
        fpt, genErr = s.fptGen.GenerateToken(ctx, dataType, normalized, []byte(blind))
    } else {
        // ff1 mode: deterministic tweak using dataType + keyVersion
        tweak := []byte(fmt.Sprintf("%s:%s", strings.ToUpper(dataType), s.fpeKeyVersion))
        fpt, genErr = s.fptGen.GenerateToken(ctx, dataType, normalized, tweak)
    }
    if genErr != nil {
        return "", genErr
    }

    // 4) Encrypt plaintext and attempt to insert (use existing InsertToken signature with 4 args)
    encStr, err := common.AESGCMEncrypt(s.aesKey, []byte(normalized))
    if err != nil {
        return "", err
    }
    encBytes := []byte(encStr)

    // Attempt insert. Your existing InsertToken signature: InsertToken(encBytes, blind, fpt, dataType)
    created, ierr := s.store.InsertToken(encBytes, blind, fpt, dataType)
    if ierr == nil && created != nil {
        // success — write-through cache if present
        if s.cache != nil {
            _ = s.cache.SetByBlindIndex(ctx, dataType, blind, fpt)
            _ = s.cache.SetByFPT(ctx, dataType, fpt, encBytes)
        }
        return fpt, nil
    }

    // Handle possible race or unique constraint violation:
    //  - someone else may have inserted the same fpt or the same blind
    //  - fetch by blind or by fpt to resolve
    if ierr != nil {
        // try to fetch by FPT (maybe inserted by another concurrent request)
        existing, gerr := s.store.GetByFPT(fpt)
        if gerr == nil && existing != nil {
            // Write to cache and return existing token
            if s.cache != nil {
                _ = s.cache.SetByBlindIndex(ctx, dataType, blind, existing.FPT)
                _ = s.cache.SetByFPT(ctx, dataType, existing.FPT, existing.EncryptedValue)
            }
            return existing.FPT, nil
        }
        // if existing is nil, attempt to SELECT by blind again (someone else inserted)
        existingByBlind, berr := s.store.GetByBlindIndex(blind)
        if berr == nil && existingByBlind != nil {
            if s.cache != nil {
                _ = s.cache.SetByBlindIndex(ctx, dataType, blind, existingByBlind.FPT)
                _ = s.cache.SetByFPT(ctx, dataType, existingByBlind.FPT, existingByBlind.EncryptedValue)
            }
            return existingByBlind.FPT, nil
        }
        // fallback: return the insert error (unknown reason)
        return "", ierr
    }

    // This should be unreachable because we returned on success or handled errors above.
    return "", fmt.Errorf("failed to allocate token")
}

