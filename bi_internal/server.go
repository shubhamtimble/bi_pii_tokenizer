package bi_internal

import (
	"encoding/json"
	"context"
	"log"
	"net/http"
	"time"
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
	fptGen        common.FPTGenerator
    fpeKeyVersion string
	r       *mux.Router
	cache   *Cache
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

	fptGen, err := common.NewFPTGeneratorFromEnv()
	if err != nil {
		log.Fatalf("failed to build FPT generator: %v", err)
	}
	fpeKeyVersion := os.Getenv("FPE_KEY_VERSION")

	s := &Server{
		store:   store,
		aesKey:  aesKey,
		hmacKey: hmacKey,
		fptGen:       fptGen,
        fpeKeyVersion: fpeKeyVersion,
		r:       mux.NewRouter(),
		cache:   nil,
	}

	// init redis cluster cache
	cache, cerr := NewCacheFromEnv()
	if cerr != nil {
		log.Printf("warning: redis cluster init failed, running without cache: %v", cerr)
	} else {
		s.cache = cache
		// synchronous preload with generous timeout; adjust as needed
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if err := s.cache.PreloadFromStore(ctx, store); err != nil {
			log.Printf("warning: cache preload failed: %v", err)
		} else {
			log.Println("cache preload completed")
		}
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
	// health
	sr.HandleFunc("/health", HealthHandler).Methods(http.MethodGet)
}

func (s *Server) Router() http.Handler {
	return s.r
}
