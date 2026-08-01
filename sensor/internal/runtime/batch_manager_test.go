package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/spool"
)

type batchStoreStub struct {
	mu       sync.Mutex
	batches  []spool.Batch
	putGate  <-chan struct{}
	putStart chan struct{}
	putErr   error
}

func (s *batchStoreStub) Put(batch spool.Batch) error {
	if s.putStart != nil {
		select {
		case s.putStart <- struct{}{}:
		default:
		}
	}
	if s.putGate != nil {
		<-s.putGate
	}
	if s.putErr != nil {
		return s.putErr
	}
	s.mu.Lock()
	s.batches = append(s.batches, batch)
	s.mu.Unlock()
	return nil
}

func (s *batchStoreStub) Pending() ([]spool.Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spool.Batch(nil), s.batches...), nil
}

func (s *batchStoreStub) ACK(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.batches {
		if s.batches[i].ID == id {
			s.batches = append(s.batches[:i], s.batches[i+1:]...)
			break
		}
	}
	return nil
}

func (*batchStoreStub) Retry(string) error     { return nil }
func (*batchStoreStub) Loss() spool.LossReport { return spool.LossReport{} }

type countingFlowUploader struct {
	mu      sync.Mutex
	batches map[string]int
}

type finalAttemptUploader struct {
	mu    sync.Mutex
	calls []string
}

func (u *finalAttemptUploader) UploadFlowBatch(_ context.Context, batch flowbatch.Batch) (flowbatch.ACK, error) {
	u.mu.Lock()
	u.calls = append(u.calls, batch.BatchID)
	u.mu.Unlock()
	if batch.BatchID == "batch-fails" {
		return flowbatch.ACK{}, errors.New("controller unavailable")
	}
	return flowbatch.ACK{BatchID: batch.BatchID, Accepted: true}, nil
}

func (u *finalAttemptUploader) called(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, called := range u.calls {
		if called == id {
			return true
		}
	}
	return false
}

func (u *countingFlowUploader) UploadFlowBatch(_ context.Context, batch flowbatch.Batch) (flowbatch.ACK, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.batches == nil {
		u.batches = make(map[string]int)
	}
	u.batches[batch.BatchID]++
	return flowbatch.ACK{BatchID: batch.BatchID, Accepted: true}, nil
}

func (u *countingFlowUploader) count(id string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.batches[id]
}

func encodedTestBatch(t *testing.T, id string) spool.Batch {
	t.Helper()
	batch := flowbatch.Batch{BatchID: id, Flows: []flowbatch.FlowRecord{{SensorID: "sensor-a"}}}
	data, err := flowbatch.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	return spool.Batch{ID: id, Data: data, CreatedAt: time.Now()}
}

func TestBatchManagerEnqueueNeverWaitsForDisk(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	store := &batchStoreStub{putGate: gate, putStart: started}
	manager, err := NewBatchManager(BatchManagerConfig{Store: store, Uploader: &countingFlowUploader{}, QueueSize: 1, UploadInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)

	if !manager.Enqueue(encodedTestBatch(t, "batch-a")) {
		t.Fatal("first batch rejected")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("writer did not receive first batch")
	}
	if !manager.Enqueue(encodedTestBatch(t, "batch-b")) {
		t.Fatal("second batch rejected while queue had capacity")
	}
	startedAt := time.Now()
	if manager.Enqueue(encodedTestBatch(t, "batch-c")) {
		t.Fatal("full bounded queue accepted another batch")
	}
	if elapsed := time.Since(startedAt); elapsed > 50*time.Millisecond {
		t.Fatalf("enqueue blocked behind disk writer for %s", elapsed)
	}
	if manager.Snapshot().LostBatches != 1 {
		t.Fatalf("lost batches = %d", manager.Snapshot().LostBatches)
	}
	close(gate)
	cancel()
	<-manager.Done()
}

func TestBatchManagerStartIsIdempotentAndUploadsOnce(t *testing.T) {
	store := &batchStoreStub{}
	uploader := &countingFlowUploader{}
	manager, err := NewBatchManager(BatchManagerConfig{Store: store, Uploader: uploader, QueueSize: 4, UploadInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)
	manager.Start(ctx)
	batch := encodedTestBatch(t, "batch-shared")
	if !manager.Enqueue(batch) {
		t.Fatal("batch rejected")
	}
	deadline := time.Now().Add(time.Second)
	for uploader.count(batch.ID) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := uploader.count(batch.ID); got != 1 {
		t.Fatalf("upload count = %d", got)
	}
	cancel()
	<-manager.Done()
}

func TestBatchManagerCountsSpoolWriteFailureAsLoss(t *testing.T) {
	store := &batchStoreStub{putErr: errors.New("disk full")}
	manager, err := NewBatchManager(BatchManagerConfig{Store: store, Uploader: &countingFlowUploader{}, QueueSize: 1, UploadInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	batch := encodedTestBatch(t, "batch-failed")
	if !manager.Enqueue(batch) {
		t.Fatal("batch was rejected before spool write")
	}
	deadline := time.Now().Add(time.Second)
	for manager.Snapshot().LostBatches == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-manager.Done()
	got := manager.Snapshot()
	if got.LostBatches != 1 || got.LostBytes != uint64(len(batch.Data)) || got.LastError == "" {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestBatchManagerFinalDrainIgnoresBackoffAndAttemptsRemainingBatches(t *testing.T) {
	failed := encodedTestBatch(t, "batch-fails")
	failed.NextAttempt = time.Now().Add(time.Hour)
	succeeds := encodedTestBatch(t, "batch-succeeds")
	succeeds.NextAttempt = time.Now().Add(time.Hour)
	store := &batchStoreStub{batches: []spool.Batch{failed, succeeds}}
	uploader := &finalAttemptUploader{}
	manager, err := NewBatchManager(BatchManagerConfig{Store: store, Uploader: uploader, QueueSize: 1, UploadInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	cancel()
	<-manager.Done()
	if !uploader.called(failed.ID) || !uploader.called(succeeds.ID) {
		t.Fatalf("final attempts = %+v", uploader.calls)
	}
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != failed.ID {
		t.Fatalf("pending after final drain = %+v", pending)
	}
	if manager.Snapshot().LastError == "" {
		t.Fatal("final drain failure telemetry was cleared by a later success")
	}
}

func TestBatchManagerShutdownWaitsForDurableWriteBeforeFinalUpload(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	store := &batchStoreStub{putGate: gate, putStart: started}
	uploader := &countingFlowUploader{}
	manager, err := NewBatchManager(BatchManagerConfig{Store: store, Uploader: uploader, QueueSize: 1, UploadInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	batch := encodedTestBatch(t, "batch-shutdown")
	if !manager.Enqueue(batch) {
		t.Fatal("batch rejected")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	cancel()
	select {
	case <-manager.Done():
		t.Fatal("manager stopped before durable write completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	select {
	case <-manager.Done():
	case <-time.After(time.Second):
		t.Fatal("manager did not finish shutdown")
	}
	if got := uploader.count(batch.ID); got != 1 {
		t.Fatalf("final upload count = %d", got)
	}
}
