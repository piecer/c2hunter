package spool

import (
	"os"
	"testing"
	"time"
)

func TestSpoolPersistsACKAndRetry(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(100, 0)
	s, err := Open(dir, Limits{MaxBytes: 1000, MaxAge: time.Hour}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Batch{ID: "batch-1", Data: []byte("payload")}); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Pending()
	if err != nil || len(pending) != 1 || pending[0].ID != "batch-1" {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	if err := s.Retry("batch-1"); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.Pending()
	if pending[0].Attempts != 1 || !pending[0].NextAttempt.Equal(now.Add(time.Second)) {
		t.Fatalf("retry not persisted: %+v", pending[0])
	}
	if err := s.ACK("batch-1"); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.Pending()
	if len(pending) != 0 {
		t.Fatal("ACK did not remove batch")
	}
}
func TestSpoolEvictsOldestBySizeAndAgeAndReportsLoss(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(100, 0)
	s, _ := Open(dir, Limits{MaxBytes: 8, MaxAge: time.Second}, func() time.Time { return now })
	if err := s.Put(Batch{ID: "old", Data: []byte("12345")}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := s.Put(Batch{ID: "new", Data: []byte("67890")}); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.Pending()
	if len(pending) != 1 || pending[0].ID != "new" {
		t.Fatalf("eviction failed: %+v", pending)
	}
	loss := s.Loss()
	if loss.Batches != 1 || loss.Bytes != 5 {
		t.Fatalf("loss not recorded: %+v", loss)
	}
	if _, err := os.Stat(dir + "/old.json"); !os.IsNotExist(err) {
		t.Fatalf("old file remains: %v", err)
	}
}
func TestSpoolRejectsUnsafeOrDuplicateID(t *testing.T) {
	s, _ := Open(t.TempDir(), Limits{MaxBytes: 100}, time.Now)
	if err := s.Put(Batch{ID: "../bad", Data: []byte("x")}); err == nil {
		t.Fatal("unsafe ID accepted")
	}
	if err := s.Put(Batch{ID: "same", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Batch{ID: "same", Data: []byte("different")}); err == nil {
		t.Fatal("duplicate ID accepted")
	}
}
