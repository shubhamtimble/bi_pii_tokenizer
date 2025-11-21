package bi_internal

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type BulkTokenizeRequest struct {
	SrcDSN      string `json:"src_dsn"`
	SrcTable    string `json:"src_table"`
	SrcColumn   string `json:"src_column"`
	DataType    string `json:"data_type"`
	TokenColumn string `json:"token_column"`
}

type BulkTokenizeResponse struct {
	Message   string `json:"message"`
	Processed int    `json:"processed"`
	Success   int    `json:"success"`
}

// HTTP handler for POST /bulk-tokenize
func (s *Server) bulkTokenizeHandler(w http.ResponseWriter, r *http.Request) {
	var req BulkTokenizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.SrcDSN == "" || req.SrcTable == "" || req.SrcColumn == "" || req.DataType == "" || req.TokenColumn == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	log.Printf("bulk-tokenize request: table=%s column=%s type=%s token_column=%s", req.SrcTable, req.SrcColumn, req.DataType, req.TokenColumn)

	processed, success, err := s.BulkTokenize(context.Background(), req.SrcDSN, req.SrcTable, req.SrcColumn, req.DataType, req.TokenColumn)
	if err != nil {
		log.Printf("bulk-tokenize error: %v", err)
		http.Error(w, "bulk-tokenize failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := BulkTokenizeResponse{
		Message:   "bulk-tokenize completed successfully",
		Processed: processed,
		Success:   success,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
