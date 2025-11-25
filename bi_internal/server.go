package bi_internal

import (
	"encoding/json"
	"context"
	"log"
	"net/http"
	"time"
	"os"
    "strings"

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
	fptGen       *common.FF1Generator
    fpeKeyVersion string
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
		fptGen:  nil,
        fpeKeyVersion: "",
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

	if strings.ToLower(os.Getenv("FPT_MODE")) == "ff1" || os.Getenv("FPE_KEY_BASE64") != "" {
		fpeB64 := os.Getenv("FPE_KEY_BASE64")
		if fpeB64 != "" {
			keyBytes, kerr := common.DecodeBase64Key(fpeB64)
			if kerr != nil {
				log.Fatalf("invalid FPE key: %v", kerr)
			}
			keyVer := os.Getenv("FPE_KEY_VERSION")
			if keyVer == "" {
				keyVer = "v1"
			}
			fg, ferr := common.NewFF1Generator(keyBytes, keyVer)
			if ferr != nil {
				log.Fatalf("failed to init FF1 generator: %v", ferr)
			}
			s.fptGen = fg
			s.fpeKeyVersion = keyVer
			log.Println("FF1 generator initialized for v3 tokenization (keyVersion=" + keyVer + ")")
		} else {
			log.Println("FPT_MODE=ff1 but FPE_KEY_BASE64 not set; ff1 disabled")
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

	sr.HandleFunc("/v3/tokenize", s.tokenizeV3Handler).Methods("POST")
    sr.HandleFunc("/v3/detokenize", s.detokenizeV3Handler).Methods("POST")

	// health
	sr.HandleFunc("/health", HealthHandler).Methods(http.MethodGet)
}

func (s *Server) Router() http.Handler {
	return s.r
}
