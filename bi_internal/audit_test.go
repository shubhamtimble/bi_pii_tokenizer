package bi_internal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNextSyncTime_Today(t *testing.T) {
	now := time.Date(2026, 4, 23, 1, 30, 0, 0, time.UTC)
	got := nextSyncTime("02:00", now)
	want := time.Date(2026, 4, 23, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestNextSyncTime_RollOver(t *testing.T) {
	now := time.Date(2026, 4, 23, 3, 0, 0, 0, time.UTC)
	got := nextSyncTime("02:00", now)
	want := time.Date(2026, 4, 24, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestNextSyncTime_Defaults(t *testing.T) {
	now := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	got := nextSyncTime("bad", now)
	want := time.Date(2026, 4, 23, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("default parse: got %v want %v", got, want)
	}
}

// newTestLogger builds an AuditLogger that skips the DB setup (db=nil so
// sync fails silently) so file-side behavior can be tested in isolation.
func newTestLogger(t *testing.T, dir string) *AuditLogger {
	t.Helper()
	a := &AuditLogger{
		dir:           dir,
		ch:            make(chan AuditEvent, 64),
		fsyncInterval: 5 * time.Millisecond,
		batchSize:     10,
		syncAt:        "02:00",
		rotateReq:     make(chan chan error, 1),
		syncNowCh:     make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
	}
	if err := a.openWAL(); err != nil {
		t.Fatalf("openWAL: %v", err)
	}
	a.wg.Add(1)
	go a.runWriter()
	return a
}

func drainWALFile(t *testing.T, path string) []AuditEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var out []AuditEvent
	for s.Scan() {
		if len(s.Bytes()) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			t.Fatalf("bad line: %v (%q)", err, s.Text())
		}
		out = append(out, ev)
	}
	return out
}

func TestAudit_WritesLinesToWAL(t *testing.T) {
	dir := t.TempDir()
	a := newTestLogger(t, dir)

	const n = 50
	for i := 0; i < n; i++ {
		a.Log(AuditEvent{
			Action:  "tokenize",
			Version: "v4",
			PIIType: "PAN",
			FPT:     "XMKPL4829Z",
			Decision: "success",
		})
	}
	// give writer goroutine time to flush via fsync ticker
	time.Sleep(30 * time.Millisecond)

	a.Close()

	evs := drainWALFile(t, filepath.Join(dir, walFileName))
	if len(evs) != n {
		t.Fatalf("expected %d events on disk, got %d", n, len(evs))
	}
	for i, ev := range evs {
		if ev.Action != "tokenize" || ev.Decision != "success" || ev.OccurredAt.IsZero() {
			t.Errorf("event %d malformed: %+v", i, ev)
		}
	}
}

func TestAudit_NilReceiverIsNoOp(t *testing.T) {
	var a *AuditLogger // nil
	a.Log(AuditEvent{Action: "x"})
	a.Close()
	// should not panic
}

func TestAudit_RotateMovesWALToPending(t *testing.T) {
	dir := t.TempDir()
	a := newTestLogger(t, dir)

	for i := 0; i < 20; i++ {
		a.Log(AuditEvent{Action: "tokenize", Version: "v4", Decision: "success"})
	}
	time.Sleep(30 * time.Millisecond)

	// request rotation (simulates the scheduler firing)
	ack := make(chan error, 1)
	a.rotateReq <- ack
	if err := <-ack; err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// pending file should now exist with all 20 events; current WAL is empty
	evs := drainWALFile(t, filepath.Join(dir, walPendingName))
	if len(evs) != 20 {
		t.Fatalf("pending should have 20 events, got %d", len(evs))
	}
	if fi, err := os.Stat(filepath.Join(dir, walFileName)); err != nil {
		t.Fatalf("new WAL not created: %v", err)
	} else if fi.Size() != 0 {
		t.Fatalf("new WAL should be empty, size=%d", fi.Size())
	}
	a.Close()
}

func TestAudit_RotateMergesExistingPending(t *testing.T) {
	dir := t.TempDir()

	// pre-seed a pending file from a hypothetical previous run
	pre := filepath.Join(dir, walPendingName)
	if err := os.WriteFile(pre, []byte(`{"occurred_at":"2026-04-22T00:00:00Z","action":"tokenize","version":"v4","decision":"success"}`+"\n"), 0640); err != nil {
		t.Fatalf("seed pending: %v", err)
	}

	a := newTestLogger(t, dir)
	for i := 0; i < 5; i++ {
		a.Log(AuditEvent{Action: "tokenize", Version: "v4", Decision: "success"})
	}
	time.Sleep(30 * time.Millisecond)

	ack := make(chan error, 1)
	a.rotateReq <- ack
	if err := <-ack; err != nil {
		t.Fatalf("rotate: %v", err)
	}

	evs := drainWALFile(t, pre)
	if len(evs) != 6 { // 1 seeded + 5 new
		t.Fatalf("merged pending should have 6 events, got %d", len(evs))
	}
	a.Close()
}
