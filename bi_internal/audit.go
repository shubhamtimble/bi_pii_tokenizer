package bi_internal

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
)

// AuditEvent is one row of pii_audit_logs (v2 schema). Plaintext PII and
// blind indexes are deliberately omitted — only the already-public FPT plus
// a one-way SHA256 fingerprint of the value (value_hash) is recorded.
type AuditEvent struct {
	OccurredAt time.Time `json:"occurred_at"`
	RequestID  string    `json:"req_id,omitempty"`
	Actor      string    `json:"actor,omitempty"`      // user id; nil/"" for tokenize
	RoleCode   string    `json:"role_code,omitempty"`  // RBAC role; set only when permission check is on
	Reason     string    `json:"reason,omitempty"`     // purpose code; nil/"" for tokenize
	Action     string    `json:"action"`               // tokenize | detokenize | *.failed
	Decision   string    `json:"decision"`             // success | failure | denied
	Version    string    `json:"version"`              // v1 | v4
	PIIType    string    `json:"pii_type,omitempty"`
	FPT        string    `json:"fpt,omitempty"`
	ValueHash  string    `json:"value_hash,omitempty"` // "sha256:<hex>"
	LatencyMS  int64     `json:"latency_ms"`
	Error      string    `json:"error,omitempty"`
	IP         string    `json:"ip,omitempty"`
}

// AuditLogger persists audit events using a local WAL file + once-per-day
// batch sync to Postgres. The request path does one non-blocking channel
// send and returns. The writer goroutine owns the file exclusively and
// groups fsyncs to keep durability cheap. At the scheduled sync time the
// WAL is rotated, the rotated file is streamed into pii_audit_logs via
// COPY FROM, and on success deleted. A recovered/leftover "pending" file
// from a previous run is synced on startup before accepting new traffic.
type AuditLogger struct {
	db  *sql.DB
	dir string

	ch            chan AuditEvent
	fsyncInterval time.Duration
	batchSize     int
	syncAt        string        // "HH:MM" UTC, used when syncInterval == 0
	syncInterval  time.Duration // if > 0, sync every N regardless of clock time

	// single writer goroutine owns these:
	file *os.File
	buf  *bufio.Writer

	rotateReq chan chan error // rotate request from scheduler -> writer
	syncNowCh chan struct{}   // manual/recovery sync trigger
	stopCh    chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
}

const (
	walFileName     = "audit.log"
	walPendingName  = "audit.pending.log"
	auditMaxLineLen = 1 << 20 // 1 MiB upper bound per line (scanner buf)
)

// pii_audit_logs schema lives in migrations/002_create_pii_audit_logs.sql and
// is applied by common.RunMigrations at server startup before this logger is
// initialized.

// NewAuditLoggerFromEnv builds the logger. Returns nil when disabled so
// AuditLogger.Log on a nil receiver is a no-op for handlers.
func NewAuditLoggerFromEnv(db *sql.DB) *AuditLogger {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_LOG_ENABLED"))); v == "false" || v == "0" || v == "no" {
		log.Println("audit: disabled via AUDIT_LOG_ENABLED")
		return nil
	}
	if db == nil {
		log.Println("audit: db handle nil — logger disabled")
		return nil
	}

	dir := strings.TrimSpace(os.Getenv("AUDIT_LOG_DIR"))
	if dir == "" {
		dir = "./audit-wal"
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("audit: mkdir %s failed (%v) — logger disabled", dir, err)
		return nil
	}

	syncAt := strings.TrimSpace(os.Getenv("AUDIT_SYNC_TIME"))
	if syncAt == "" {
		syncAt = "02:00"
	}

	// AUDIT_SYNC_INTERVAL takes precedence over AUDIT_SYNC_TIME when set.
	// Accepts any Go duration string (e.g. "1h", "30m", "2h15m", "10s").
	var syncInterval time.Duration
	if v := strings.TrimSpace(os.Getenv("AUDIT_SYNC_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			syncInterval = d
		} else {
			log.Printf("audit: invalid AUDIT_SYNC_INTERVAL=%q (%v) — falling back to daily AUDIT_SYNC_TIME", v, err)
		}
	}

	a := &AuditLogger{
		db:            db,
		dir:           dir,
		ch:            make(chan AuditEvent, envPositiveInt("AUDIT_BUFFER_SIZE", 4096)),
		fsyncInterval: time.Duration(envPositiveInt("AUDIT_FSYNC_INTERVAL_MS", 5)) * time.Millisecond,
		batchSize:     envPositiveInt("AUDIT_DB_BATCH_SIZE", 500),
		syncAt:        syncAt,
		syncInterval:  syncInterval,
		rotateReq:     make(chan chan error, 1),
		syncNowCh:     make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
	}

	if err := a.openWAL(); err != nil {
		log.Printf("audit: open WAL failed (%v) — logger disabled", err)
		return nil
	}

	a.wg.Add(2)
	go a.runWriter()
	go a.runScheduler()

	// Recovery: if a pending file exists from a previous crash or failed
	// sync, fire a sync immediately.
	if _, err := os.Stat(filepath.Join(dir, walPendingName)); err == nil {
		log.Println("audit: found pending WAL on startup — scheduling recovery sync")
		a.triggerSync()
	}

	if a.syncInterval > 0 {
		log.Printf("audit: WAL ready dir=%s sync_every=%s buffer=%d batch=%d fsync=%s",
			dir, a.syncInterval, cap(a.ch), a.batchSize, a.fsyncInterval)
	} else {
		log.Printf("audit: WAL ready dir=%s sync_at=%s UTC buffer=%d batch=%d fsync=%s",
			dir, syncAt, cap(a.ch), a.batchSize, a.fsyncInterval)
	}
	return a
}

func (a *AuditLogger) openWAL() error {
	f, err := os.OpenFile(
		filepath.Join(a.dir, walFileName),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0640,
	)
	if err != nil {
		return err
	}
	a.file = f
	a.buf = bufio.NewWriterSize(f, 64*1024)
	return nil
}

// Log enqueues an event. Non-blocking: if the buffer is full the event is
// dropped with a warning log and the request path keeps its latency budget.
func (a *AuditLogger) Log(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	select {
	case a.ch <- ev:
	default:
		log.Printf("audit: channel full — dropping event action=%s decision=%s", ev.Action, ev.Decision)
	}
}

// Close drains the channel, fsyncs the WAL, stops goroutines. Safe twice.
func (a *AuditLogger) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		close(a.stopCh)
		close(a.ch)
		a.wg.Wait()
	})
}

// TriggerSync forces an immediate rotation+sync cycle (used in tests and on
// startup recovery). Non-blocking; a second trigger while one is in flight
// is ignored.
func (a *AuditLogger) triggerSync() {
	select {
	case a.syncNowCh <- struct{}{}:
	default:
	}
}

// runWriter is the single owner of the WAL file descriptor. It drains the
// channel, groups fsyncs, and handles rotation requests from the scheduler
// so there is never more than one writer touching the file.
func (a *AuditLogger) runWriter() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.fsyncInterval)
	defer ticker.Stop()

	dirty := false
	for {
		select {
		case ev, ok := <-a.ch:
			if !ok {
				_ = a.flushSync()
				_ = a.file.Close()
				return
			}
			if err := a.writeOne(ev); err != nil {
				log.Printf("audit: write failed: %v", err)
				continue
			}
			dirty = true

		case <-ticker.C:
			if dirty {
				if err := a.flushSync(); err != nil {
					log.Printf("audit: fsync failed: %v", err)
				}
				dirty = false
			}

		case ack := <-a.rotateReq:
			err := a.rotateLocked()
			dirty = false
			ack <- err

		case <-a.stopCh:
			_ = a.flushSync()
			_ = a.file.Close()
			return
		}
	}
}

func (a *AuditLogger) writeOne(ev AuditEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := a.buf.Write(b); err != nil {
		return err
	}
	return a.buf.WriteByte('\n')
}

func (a *AuditLogger) flushSync() error {
	if err := a.buf.Flush(); err != nil {
		return err
	}
	return a.file.Sync()
}

// rotateLocked is called from the writer goroutine. It closes the current
// WAL, renames (or appends) it to the pending slot, then opens a fresh WAL.
// After this returns the syncer can safely read the pending file.
func (a *AuditLogger) rotateLocked() error {
	if err := a.flushSync(); err != nil {
		log.Printf("audit rotate: flush failed: %v", err)
	}
	if err := a.file.Close(); err != nil {
		log.Printf("audit rotate: close failed: %v", err)
	}

	src := filepath.Join(a.dir, walFileName)
	pending := filepath.Join(a.dir, walPendingName)

	// If a pending file already exists (e.g. previous sync failed), append
	// the current WAL onto it so we sync both together.
	if _, err := os.Stat(pending); err == nil {
		if err := appendFileContents(pending, src); err != nil {
			log.Printf("audit rotate: append to existing pending failed: %v", err)
		} else {
			_ = os.Remove(src)
		}
	} else if os.IsNotExist(err) {
		// Normal path: rename. If the WAL doesn't exist (empty day), skip.
		if _, serr := os.Stat(src); serr == nil {
			if rerr := os.Rename(src, pending); rerr != nil {
				log.Printf("audit rotate: rename failed: %v", rerr)
			}
		}
	}

	return a.openWAL()
}

func appendFileContents(dst, src string) error {
	df, err := os.OpenFile(dst, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer df.Close()
	sf, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer sf.Close()
	if _, err := io.Copy(df, sf); err != nil {
		return err
	}
	return df.Sync()
}

// runScheduler runs in one of two modes:
//   - interval mode (syncInterval > 0): rotate+sync every N
//   - daily-time mode (syncInterval == 0): rotate+sync at the next syncAt UTC
//
// Either mode can be short-circuited by a manual trigger via syncNowCh.
func (a *AuditLogger) runScheduler() {
	defer a.wg.Done()

	if a.syncInterval > 0 {
		ticker := time.NewTicker(a.syncInterval)
		defer ticker.Stop()
		log.Printf("audit: interval scheduler — first sync in %s", a.syncInterval)
		for {
			select {
			case <-ticker.C:
				a.rotateAndSync()
			case <-a.syncNowCh:
				a.rotateAndSync()
			case <-a.stopCh:
				return
			}
		}
	}

	for {
		next := nextSyncTime(a.syncAt, time.Now().UTC())
		wait := time.Until(next)
		log.Printf("audit: next scheduled sync at %s UTC (in %s)", next.Format(time.RFC3339), wait.Round(time.Second))

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-a.syncNowCh:
			timer.Stop()
		case <-a.stopCh:
			timer.Stop()
			return
		}
		a.rotateAndSync()
	}
}

// rotateAndSync asks the writer to rotate, then syncs the pending file to
// Postgres. On any failure the pending file stays on disk and the next
// cycle (or startup) will retry it.
func (a *AuditLogger) rotateAndSync() {
	ack := make(chan error, 1)
	a.rotateReq <- ack
	if err := <-ack; err != nil {
		log.Printf("audit sync: rotate failed (%v) — skipping this cycle", err)
		return
	}
	n, err := a.syncPendingToDB()
	if err != nil {
		log.Printf("audit sync: DB write failed (%v) — pending file retained for next cycle", err)
		return
	}
	pending := filepath.Join(a.dir, walPendingName)
	if err := os.Remove(pending); err != nil && !os.IsNotExist(err) {
		log.Printf("audit sync: remove pending failed: %v", err)
		return
	}
	// Only announce completion when rows were actually synced. With a short
	// sync interval an idle cycle (nothing pending) would otherwise log every
	// tick forever.
	if n > 0 {
		log.Println("audit sync: complete, pending WAL cleared")
	}
}

func (a *AuditLogger) syncPendingToDB() (int, error) {
	pending := filepath.Join(a.dir, walPendingName)
	f, err := os.Open(pending)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), auditMaxLineLen)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	batch := make([]AuditEvent, 0, a.batchSize)
	total := 0
	bad := 0

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := a.insertBatch(ctx, batch); err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			bad++
			continue
		}
		batch = append(batch, ev)
		if len(batch) >= a.batchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return total, fmt.Errorf("scan: %w", err)
	}
	if err := flush(); err != nil {
		return total, err
	}
	// Only log when something was actually synced; an idle cycle (0 rows) must
	// stay silent or this fires every sync interval forever.
	if total > 0 || bad > 0 {
		log.Printf("audit sync: inserted %d rows (skipped %d malformed lines)", total, bad)
	}
	return total, nil
}

func (a *AuditLogger) insertBatch(ctx context.Context, evs []AuditEvent) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("pii_audit_logs",
		"occurred_at", "req_id", "actor", "reason", "action", "decision",
		"version", "pii_type", "fpt", "value_hash", "latency_ms", "error", "ip",
		"role_code",
	))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, ev := range evs {
		if _, err := stmt.ExecContext(ctx,
			ev.OccurredAt,
			nullIfEmpty(ev.RequestID),
			nullIfEmpty(ev.Actor),
			nullIfEmpty(ev.Reason),
			ev.Action,
			ev.Decision,
			ev.Version,
			nullIfEmpty(ev.PIIType),
			nullIfEmpty(ev.FPT),
			nullIfEmpty(ev.ValueHash),
			ev.LatencyMS,
			nullIfEmpty(ev.Error),
			nullIfEmpty(ev.IP),
			nullIfEmpty(ev.RoleCode),
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		_ = stmt.Close()
		_ = tx.Rollback()
		return err
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func nextSyncTime(hhmm string, now time.Time) time.Time {
	parts := strings.Split(hhmm, ":")
	h, m := 2, 0
	if len(parts) >= 1 {
		if v, err := strconv.Atoi(parts[0]); err == nil && v >= 0 && v <= 23 {
			h = v
		}
	}
	if len(parts) >= 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil && v >= 0 && v <= 59 {
			m = v
		}
	}
	candidate := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, time.UTC)
	if !candidate.After(now) {
		candidate = candidate.Add(24 * time.Hour)
	}
	return candidate
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func envPositiveInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
