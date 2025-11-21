package bi_internal

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"bi_pii_tokenizer/models"
)

// Cache uses a single Redis client (no ClusterClient) for all operations.
type Cache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewCacheFromEnv initializes a single-node Redis client using env:
// REDIS_ADDR = "host:6379" (preferred)
// REDIS_PASS (optional)
// CACHE_TTL_SECONDS (optional, default 7 days)
// REDIS_DIAL_TIMEOUT_SEC / REDIS_RW_TIMEOUT_SEC (optional)
func NewCacheFromEnv() (*Cache, error) {
	ttl := 7 * 24 * time.Hour
	if v := os.Getenv("CACHE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			ttl = time.Duration(secs) * time.Second
		}
	}

	dialTimeout := 5 * time.Second
	if v := os.Getenv("REDIS_DIAL_TIMEOUT_SEC"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 {
			dialTimeout = time.Duration(s) * time.Second
		}
	}
	rwTimeout := 5 * time.Second
	if v := os.Getenv("REDIS_RW_TIMEOUT_SEC"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 {
			rwTimeout = time.Duration(s) * time.Second
		}
	}

	pass := strings.TrimSpace(os.Getenv("REDIS_PASS"))

	// Prefer explicit REDIS_ADDR
	addr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	// If REDIS_ADDR empty but REDIS_CLUSTER_ADDRS present, use the first address as single-node fallback
	if addr == "" {
		if addrsCSV := strings.TrimSpace(os.Getenv("REDIS_CLUSTER_ADDRS")); addrsCSV != "" {
			parts := strings.Split(addrsCSV, ",")
			if len(parts) > 0 {
				addr = strings.TrimSpace(parts[0])
				log.Printf("redis: using first address from REDIS_CLUSTER_ADDRS as single-node addr: %s", addr)
			}
		}
	}

	if addr == "" {
		return nil, fmt.Errorf("REDIS_ADDR not set (or REDIS_CLUSTER_ADDRS empty). set REDIS_ADDR for single-node redis")
	}

	opts := &redis.Options{
		Addr:         addr,
		Password:     pass,
		DialTimeout:  dialTimeout,
		ReadTimeout:  rwTimeout,
		WriteTimeout: rwTimeout,
	}

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed (%s): %w", addr, err)
	}

	log.Printf("redis: connected in SINGLE-NODE mode (addr=%s)", addr)
	return &Cache{client: client, ttl: ttl}, nil
}

func (c *Cache) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

func blindCacheKey(dataType, blindIndex string) string {
	return fmt.Sprintf("pii:v1:%s:blind:%s", dataType, blindIndex)
}
func fptCacheKey(dataType, fpt string) string {
	return fmt.Sprintf("pii:v1:%s:fpt:%s", dataType, fpt)
}

// internal helpers
func (c *Cache) get(ctx context.Context, key string) (string, error) {
	if c == nil || c.client == nil {
		return "", nil
	}
	res, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return res, err
}

func (c *Cache) set(ctx context.Context, key string, value interface{}) error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Set(ctx, key, value, c.ttl).Err()
}

// GetByBlindIndex returns the FPT (or empty string if not found).
func (c *Cache) GetByBlindIndex(ctx context.Context, dataType, blindIndex string) (string, error) {
	if c == nil || c.client == nil {
		return "", nil
	}
	k := blindCacheKey(dataType, blindIndex)
	return c.get(ctx, k)
}

// SetByBlindIndex sets blind -> fpt
func (c *Cache) SetByBlindIndex(ctx context.Context, dataType, blindIndex, fpt string) error {
	if c == nil || c.client == nil {
		return nil
	}
	k := blindCacheKey(dataType, blindIndex)
	return c.set(ctx, k, fpt)
}

// GetByFPT returns encrypted_value (or empty string if not found).
func (c *Cache) GetByFPT(ctx context.Context, dataType, fpt string) (string, error) {
	if c == nil || c.client == nil {
		return "", nil
	}
	k := fptCacheKey(dataType, fpt)
	return c.get(ctx, k)
}

// SetByFPT sets fpt -> encrypted_value. Accepts encryptedValue as []byte.
func (c *Cache) SetByFPT(ctx context.Context, dataType, fpt string, encryptedValue []byte) error {
	if c == nil || c.client == nil {
		return nil
	}
	k := fptCacheKey(dataType, fpt)
	return c.set(ctx, k, string(encryptedValue))
}

// PreloadFromStore streams tokens directly from DB to Redis with pipelined sets using single client.
func (c *Cache) PreloadFromStore(ctx context.Context, store *models.Store) error {
	if c == nil || c.client == nil {
		return nil
	}

	log.Println("cache: starting preload from store (streaming)")

	const batchSize = 1000

	rows, err := store.DB().QueryContext(ctx, `SELECT data_type, blind_index, fpt, encrypted_value FROM pii_tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()

	pipe := c.client.Pipeline()
	n := 0
	batchCount := 0

	for rows.Next() {
		var dataType, blindIndex, fpt string
		var encryptedValue []byte
		if err := rows.Scan(&dataType, &blindIndex, &fpt, &encryptedValue); err != nil {
			log.Printf("cache preload: row scan error: %v", err)
			continue
		}

		pipe.Set(ctx, blindCacheKey(dataType, blindIndex), fpt, c.ttl)
		pipe.Set(ctx, fptCacheKey(dataType, fpt), string(encryptedValue), c.ttl)

		n++
		batchCount++

		if batchCount >= batchSize {
			if _, err := pipe.Exec(ctx); err != nil {
				log.Printf("cache preload pipeline exec error: %v", err)
			}
			pipe = c.client.Pipeline()
			batchCount = 0
			log.Printf("cache preload: processed %d entries so far", n)
		}
	}

	if batchCount > 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			log.Printf("cache preload final pipeline exec error: %v", err)
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("cache preload rows iteration error: %v", err)
	}

	log.Printf("cache: preload complete, processed %d tokens", n)
	return nil
}
