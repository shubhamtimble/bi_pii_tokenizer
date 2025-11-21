// package main

// import (
// 	"database/sql"
// 	"log"
// 	"net/http"
// 	"os"
// 	"time"

// 	_ "github.com/lib/pq"

// 	"bi_pii_tokenizer/bi_internal"
// 	"bi_pii_tokenizer/models"
// 	"bi_pii_tokenizer/common"
// )

// func main() {
// 	dsn := os.Getenv("DATABASE_URL")
// 	if dsn == "" {
// 		log.Fatalf("DATABASE_URL is required")
// 	}

// 	db, err := sql.Open("postgres", dsn)
// 	if err != nil {
// 		log.Fatalf("open db: %v", err)
// 	}
// 	db.SetMaxOpenConns(20)
// 	db.SetMaxIdleConns(5)
// 	db.SetConnMaxLifetime(time.Minute * 15)

// 	if err = db.Ping(); err != nil {
// 		log.Fatalf("ping db: %v", err)
// 	}

// 	if err := common.RunMigrations(db, "migrations/001_create_pii_tokens.sql"); err != nil {
// 		log.Fatalf("migration failed: %v", err)
// 	}

// 	store := models.NewStore(db)

// 	srv := bi_internal.NewServer(store)

// 	addr := os.Getenv("HTTP_ADDR")
// 	if addr == "" {
// 		addr = ":8081"
// 	}
// 	log.Printf("starting server on %s", addr)
// 	log.Fatal(http.ListenAndServe(addr, srv.Router()))
// }


package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"bi_pii_tokenizer/bi_internal"
	"bi_pii_tokenizer/models"
	"bi_pii_tokenizer/common"
)

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get API key from environment
		expectedAPIKey := os.Getenv("API_KEY")
		if expectedAPIKey == "" {
			log.Println("Warning: Api Key Not Found For Login User")
		}

		// Get API key from request header
		apiKey := r.Header.Get("X-API-Key")

		// Validate API key
		if apiKey == "" {
			http.Error(w, `{"error": "Missing API key"}`, http.StatusUnauthorized)
			return
		}
		

		if apiKey != expectedAPIKey {
			http.Error(w, `{"error": "Invalid API key"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-API-Key")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Load DB connection string
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatalf("DATABASE_URL is required")
	}

	// Open DB connection pool
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 15)

	if err = db.Ping(); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	// Run migrations before server starts
	if err := common.RunMigrations(db, "migrations/001_create_pii_tokens.sql"); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	// Create datastore wrapper
	store := models.NewStore(db)

	// Create server (this initializes Redis Cluster + preload)
	srv := bi_internal.NewServer(store)

	handler := corsMiddleware(apiKeyMiddleware(srv.Router()))

	// Start HTTP server
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	log.Printf("starting server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
