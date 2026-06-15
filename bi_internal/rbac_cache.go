package bi_internal

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// RBAC is the role-based access control layer. It holds an in-memory snapshot of
// roles + permissions (refreshed periodically and on admin writes) and falls back
// to the DB only when the snapshot has never successfully loaded. It is a no-op
// whenever `enabled` is false, which keeps the service's existing behavior
// byte-identical when PERMISSION_CHECK_ENABLED is off.
type RBAC struct {
	store   *rbacStore
	enabled bool
	ttl     time.Duration

	mu         sync.RWMutex
	roles      map[string]Role
	endpoint   map[string]bool
	pii        map[string]PIIPerm
	loaded     bool
	lastReload time.Time

	stopCh chan struct{}
	once   sync.Once
}

// Enabled reports whether the permission layer is on.
func (r *RBAC) Enabled() bool { return r != nil && r.enabled }

// TTLSeconds returns the cache refresh interval in seconds.
func (r *RBAC) TTLSeconds() int {
	if r == nil {
		return 0
	}
	return int(r.ttl.Seconds())
}

// LastReload returns the time of the last successful cache load and whether one
// has happened.
func (r *RBAC) LastReload() (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastReload, !r.lastReload.IsZero()
}

// NewRBACFromEnv builds the RBAC layer. It always returns a non-nil value; when
// PERMISSION_CHECK_ENABLED is not true the layer is disabled and every check is
// skipped. When enabled it loads the cache once and starts the auto-refresh loop.
func NewRBACFromEnv(db *sql.DB) *RBAC {
	enabled := envBool("PERMISSION_CHECK_ENABLED", false)
	ttl := time.Duration(envPositiveInt("PERMISSION_CACHE_TTL_SECONDS", 60)) * time.Second

	r := &RBAC{
		store:    &rbacStore{db: db},
		enabled:  enabled,
		ttl:      ttl,
		roles:    map[string]Role{},
		endpoint: map[string]bool{},
		pii:      map[string]PIIPerm{},
		stopCh:   make(chan struct{}),
	}

	if !enabled {
		log.Println("rbac: permission check DISABLED (PERMISSION_CHECK_ENABLED not true)")
		return r
	}

	if err := r.ReloadCache(context.Background()); err != nil {
		log.Printf("rbac: initial cache load failed (%v) — will use DB fallback until a reload succeeds", err)
	}
	r.StartAutoRefresh()
	log.Printf("rbac: permission check ENABLED (cache ttl=%s)", ttl)
	return r
}

// ReloadCache loads a fresh snapshot from the DB and atomically swaps it in.
func (r *RBAC) ReloadCache(ctx context.Context) error {
	snap, err := r.store.LoadSnapshot(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.roles = snap.roles
	r.endpoint = snap.endpoint
	r.pii = snap.pii
	r.loaded = true
	r.lastReload = time.Now().UTC()
	r.mu.Unlock()
	return nil
}

// StartAutoRefresh reloads the cache every ttl until Stop is called.
func (r *RBAC) StartAutoRefresh() {
	go func() {
		ticker := time.NewTicker(r.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.ReloadCache(context.Background()); err != nil {
					log.Printf("rbac: auto-refresh reload failed: %v", err)
				}
			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop ends the auto-refresh loop (safe to call multiple times).
func (r *RBAC) Stop() {
	r.once.Do(func() { close(r.stopCh) })
}

// GetRole returns the role and whether it exists. When the cache is loaded the
// snapshot is authoritative (no DB hit); otherwise it falls back to the DB.
func (r *RBAC) GetRole(ctx context.Context, roleCode string) (Role, bool, error) {
	r.mu.RLock()
	loaded := r.loaded
	role, ok := r.roles[roleCode]
	r.mu.RUnlock()
	if loaded {
		return role, ok, nil
	}
	return r.store.GetRoleFromDB(ctx, roleCode)
}

// CheckEndpointPermission returns whether the role may call the given action.
// A missing permission row is a deny (false), not an error.
func (r *RBAC) CheckEndpointPermission(ctx context.Context, roleCode string, action EndpointAction) (bool, error) {
	r.mu.RLock()
	loaded := r.loaded
	allowed, ok := r.endpoint[endpointKey(roleCode, action)]
	r.mu.RUnlock()
	if loaded {
		if !ok {
			return false, nil
		}
		return allowed, nil
	}
	return r.store.CheckEndpointPermissionFromDB(ctx, roleCode, action)
}

// getPIIPerm returns the (role, pii_type) permission, whether it exists, and an
// infra error (only possible on the DB-fallback path).
func (r *RBAC) getPIIPerm(ctx context.Context, roleCode, piiType string) (PIIPerm, bool, error) {
	r.mu.RLock()
	loaded := r.loaded
	p, ok := r.pii[piiKey(roleCode, piiType)]
	r.mu.RUnlock()
	if loaded {
		return p, ok, nil
	}
	return r.store.GetPIIPermFromDB(ctx, roleCode, piiType)
}

// envBool parses a boolean-ish env var (true/1/yes => true).
func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}
