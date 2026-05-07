package bi_internal

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"

	"bi_pii_tokenizer/common"
	"bi_pii_tokenizer/models"
)
type HealthStatusResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}


type Server struct {
	store   *models.Store
	aesKey  []byte
	hmacKey []byte
	r       *mux.Router
	cache   *Cache
	ff1Gen  *common.FF1GeneratorV4
	audit   *AuditLogger
}

// NewServer creates a server and initializes keys + redis cluster cache.
// It will attempt to preload the cache synchronously from the DB store (may be slow for very large datasets).
func NewServer(store *models.Store) *Server {
	// load keys from env (panic if missing)
	aesKeyStr := common.MustEnv("AES_KEY_BASE64")
	hmacKeyStr := common.MustEnv("HMAC_KEY_BASE64")
	aesKey, err := common.DecodeBase64Key(aesKeyStr)
	if err != nil {
		panic("invalid AES key: " + err.Error())
	}
	hmacKey, err := common.DecodeBase64Key(hmacKeyStr)
	if err != nil {
		panic("invalid HMAC key: " + err.Error())
	}

	s := &Server{
		store:   store,
		aesKey:  aesKey,
		hmacKey: hmacKey,
		r:       mux.NewRouter(),
		cache:   nil,
	}

	// v4: optional FF1 generator. If FPE_KEY_BASE64 is absent the /v4/*
	// endpoints return 503; legacy endpoints are unaffected.
	if fpeB64 := os.Getenv("FPE_KEY_BASE64"); fpeB64 != "" {
		keyBytes, kerr := common.DecodeBase64Key(fpeB64)
		if kerr != nil {
			log.Fatalf("invalid FPE_KEY_BASE64: %v", kerr)
		}
		keyVer := os.Getenv("FPE_KEY_VERSION")
		if keyVer == "" {
			keyVer = "v1"
		}
		gen, gerr := common.NewFF1GeneratorV4(keyBytes, keyVer)
		if gerr != nil {
			log.Fatalf("init FF1 v4: %v", gerr)
		}
		s.ff1Gen = gen
		log.Printf("v4 FF1 generator ready (keyVersion=%s)", keyVer)
	} else {
		log.Println("v4 FF1 generator disabled (FPE_KEY_BASE64 not set)")
	}

	s.audit = NewAuditLoggerFromEnv(store.DB())

	// init redis cache. Preload runs in the background so the HTTP listener
	// comes up immediately; the first few requests after startup may miss
	// cache and go straight to DB (the normal cache-miss path).
	cache, cerr := NewCacheFromEnv()
	if cerr != nil {
		log.Printf("warning: redis init failed, running without cache: %v", cerr)
	} else {
		s.cache = cache
		s.cache.PreloadFromStoreBackground(store)
	}

	s.routes()
	return s
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthStatusResponse{
		Message: "Format Preserving Tokenization Service is working",
		Status:  "Fine",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}


func (s *Server) routes() {
	sr := s.r.PathPrefix("/api/fpt-tokenization").Subrouter()
	sr.HandleFunc("/tokenize", s.tokenizeHandler).Methods("POST")
	sr.HandleFunc("/detokenize", s.detokenizeHandler).Methods("POST")
	sr.HandleFunc("/bulk-tokenize", s.bulkTokenizeHandler).Methods("POST")
	sr.HandleFunc("/v4/tokenize", s.tokenizeV4Handler).Methods("POST")
	sr.HandleFunc("/v4/detokenize", s.detokenizeV4Handler).Methods("POST")
	sr.HandleFunc("/audit/events", s.auditEventsHandler).Methods(http.MethodGet)
	// health
	sr.HandleFunc("/health", HealthHandler).Methods(http.MethodGet)
}

func (s *Server) Router() http.Handler {
	return s.r
}
