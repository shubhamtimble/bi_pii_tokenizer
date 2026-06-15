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
	rbac    *RBAC
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

	// RBAC permission layer. Always constructed; a no-op unless
	// PERMISSION_CHECK_ENABLED is true. Loads its own in-memory permission cache
	// (separate from the Redis token cache) and refreshes it periodically.
	s.rbac = NewRBACFromEnv(store.DB())

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

	// Protected endpoints — wrapped with the RBAC endpoint gate (pass-through
	// when PERMISSION_CHECK_ENABLED is false).
	sr.Handle("/tokenize", s.requireEndpoint(ActionTokenize, http.HandlerFunc(s.tokenizeHandler))).Methods(http.MethodPost)
	sr.Handle("/detokenize", s.requireEndpoint(ActionDetokenize, http.HandlerFunc(s.detokenizeHandler))).Methods(http.MethodPost)
	sr.Handle("/v4/tokenize", s.requireEndpoint(ActionTokenize, http.HandlerFunc(s.tokenizeV4Handler))).Methods(http.MethodPost)
	sr.Handle("/v4/detokenize", s.requireEndpoint(ActionDetokenize, http.HandlerFunc(s.detokenizeV4Handler))).Methods(http.MethodPost)
	sr.Handle("/audit/events", s.requireEndpoint(ActionAuditRead, http.HandlerFunc(s.auditEventsHandler))).Methods(http.MethodGet)

	// health — intentionally unguarded by RBAC (still behind the global X-API-Key)
	sr.HandleFunc("/health", HealthHandler).Methods(http.MethodGet)

	// Admin permission-management APIs.
	sr.Handle("/admin/roles", s.requireEndpoint(ActionRoleManage, http.HandlerFunc(s.adminCreateRoleHandler))).Methods(http.MethodPost)
	sr.Handle("/admin/roles", s.requireEndpoint(ActionRoleManage, http.HandlerFunc(s.adminListRolesHandler))).Methods(http.MethodGet)
	sr.Handle("/admin/roles/{role_code}", s.requireEndpoint(ActionRoleManage, http.HandlerFunc(s.adminUpdateRoleHandler))).Methods(http.MethodPut)
	sr.Handle("/admin/roles/{role_code}/endpoint-permissions", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminGetEndpointPermsHandler))).Methods(http.MethodGet)
	sr.Handle("/admin/roles/{role_code}/endpoint-permissions", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminPutEndpointPermsHandler))).Methods(http.MethodPut)
	sr.Handle("/admin/roles/{role_code}/pii-permissions", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminGetPIIPermsHandler))).Methods(http.MethodGet)
	sr.Handle("/admin/roles/{role_code}/pii-permissions", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminPutPIIPermsHandler))).Methods(http.MethodPut)
	sr.Handle("/admin/permissions/reload-cache", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminReloadCacheHandler))).Methods(http.MethodPost)
	sr.Handle("/admin/overview", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminOverviewHandler))).Methods(http.MethodGet)
	sr.Handle("/admin/permission-audit", s.requireEndpoint(ActionPermissionManage, http.HandlerFunc(s.adminPermissionAuditHandler))).Methods(http.MethodGet)
}

func (s *Server) Router() http.Handler {
	return s.r
}
