package bi_internal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"bi_pii_tokenizer/common"
)

var identRE = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// BulkTokenize reads values from a target DB and sends each PII to the /tokenize HTTP API.
// After successful tokenization it writes the returned FPT into the provided tokenColumn
// of the exact source table row (using ctid). Returns (processedRows, successCount, error).
func (s *Server) BulkTokenize(ctx context.Context, srcDSN, srcTable, srcColumn, dataType, tokenColumn string) (int, int, error) {
	// validation to avoid SQL injection via table/column names
	if !identRE.MatchString(srcTable) || !identRE.MatchString(srcColumn) || !identRE.MatchString(tokenColumn) {
		return 0, 0, errors.New("invalid table, column or token_column name")
	}

	srcDB, err := sql.Open("postgres", srcDSN)
	if err != nil {
		return 0, 0, fmt.Errorf("open src db: %w", err)
	}
	srcDB.SetConnMaxLifetime(time.Minute * 5)
	srcDB.SetMaxOpenConns(5)
	defer srcDB.Close()

	// Select ctid and the PII column so we can update the exact row later using ctid
	query := fmt.Sprintf("SELECT ctid, %s FROM %s", srcColumn, srcTable)
	rows, err := srcDB.QueryContext(ctx, query)
	if err != nil {
		return 0, 0, fmt.Errorf("query source: %w", err)
	}
	defer rows.Close()

	var (
		ctidVal sql.NullString
		value   sql.NullString
	)

	processed := 0
	success := 0

	client := &http.Client{Timeout: 30 * time.Second}
	tokenizeURL := "http://localhost:8081/tokenize"
	if env := common.MaybeEnv("TOKENIZE_URL"); env != "" {
		tokenizeURL = env
	}

	for rows.Next() {
		if err := rows.Scan(&ctidVal, &value); err != nil {
			log.Printf("bulk: scan error: %v", err)
			continue
		}
		processed++

		if !ctidVal.Valid {
			log.Printf("bulk: row %d - missing ctid (unexpected), skipping", processed)
			continue
		}
		ctid := ctidVal.String

		if !value.Valid {
			log.Printf("bulk: row %d - null value, skipping", processed)
			continue
		}
		rawVal := strings.TrimSpace(value.String)
		if rawVal == "" {
			log.Printf("bulk: row %d - empty string, skipping", processed)
			continue
		}

		// Normalize same as Tokenize API: PAN -> uppercase
		var normalized string
		switch strings.ToUpper(strings.TrimSpace(dataType)) {
		case "PAN":
			normalized = strings.ToUpper(rawVal)
		default:
			normalized = rawVal
		}

		// Optional pre-check: skip if already tokenized in tokenization DB
		blind := common.HMACBlindIndex(s.hmacKey, normalized)
		if existing, err := s.store.GetByBlindIndex(blind); err == nil && existing != nil {
			log.Printf("bulk: row %d - already tokenized (fpt=%s), skipping HTTP call", processed, existing.FPT)
			// Also ensure token is written to source row if missing: try update source if token column empty
			if err := writeTokenToSourceRow(ctx, srcDB, srcTable, tokenColumn, ctid, existing.FPT); err != nil {
				log.Printf("bulk: row %d - warning: failed to write existing token to source row: %v", processed, err)
			}
			continue
		}

		// Build request to /tokenize
		reqBody := map[string]string{
			"pii_type":  dataType,
			"pii_value": normalized,
		}
		b, _ := json.Marshal(reqBody)

		reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenizeURL, bytes.NewReader(b))
		if err != nil {
			cancel()
			log.Printf("bulk: row %d - create request error: %v", processed, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			log.Printf("bulk: row %d - http error calling tokenize: %v", processed, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("bulk: row %d - tokenize API returned status %d body=%s", processed, resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}

		var tr struct {
			FPT string `json:"fpt"`
		}
		if err := json.Unmarshal(body, &tr); err != nil {
			log.Printf("bulk: row %d - invalid tokenize response: %v body=%s", processed, err, strings.TrimSpace(string(body)))
			continue
		}
		if tr.FPT == "" {
			log.Printf("bulk: row %d - tokenize returned empty fpt (body=%s)", processed, strings.TrimSpace(string(body)))
			continue
		}

		// write token into source row using ctid to target exact row
		if err := writeTokenToSourceRow(ctx, srcDB, srcTable, tokenColumn, ctid, tr.FPT); err != nil {
			log.Printf("bulk: row %d - failed to write token to source row: %v", processed, err)
			continue
		}

		success++
		log.Printf("bulk: row %d - tokenized fpt=%s and wrote to source row (ctid=%s)", processed, tr.FPT, ctid)
	}

	if err := rows.Err(); err != nil {
		return processed, success, fmt.Errorf("rows error: %w", err)
	}
	log.Printf("bulk-tokenize completed: processed=%d success=%d", processed, success)
	return processed, success, nil
}

// writeTokenToSourceRow updates the given tokenColumn for the row identified by ctid.
// It only sets the token when the token column is currently NULL/empty to avoid overwriting.
func writeTokenToSourceRow(ctx context.Context, db *sql.DB, table, tokenColumn, ctid, fpt string) error {
	updateSQL := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE ctid = $2 AND (COALESCE(%s, '') = '')", table, tokenColumn, tokenColumn)
	res, err := db.ExecContext(ctx, updateSQL, fpt, ctid)
	if err != nil {
		return fmt.Errorf("update exec: %w", err)
	}
	// Optionally check rows affected:
	if ra, err := res.RowsAffected(); err == nil && ra == 0 {
		// nothing updated (maybe token column already set) — return nil (not fatal)
		return nil
	}
	return nil
}
